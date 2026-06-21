#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <afl-fuzz.h>
#include <alloc-inl.h>
#include "ca_engine.h"
#include "mutation_plan.h"

#ifndef CA_ENGINE_VARIANT
#error CA_ENGINE_VARIANT must be defined as 1 (xor) or 2 (growing)
#endif

#if CA_ENGINE_VARIANT == 1
#include "xor_engine.h"
#define CA_ENGINE_NAME "ca_mutator_xor"
#elif CA_ENGINE_VARIANT == 2
#include "growing_engine.h"
#define CA_ENGINE_NAME "ca_mutator_growing"
#else
#error Unknown CA_ENGINE_VARIANT
#endif

typedef struct {
    afl_state_t *afl;
    ca_engine_t *engine;

    uint8_t *plan_out_buf;
    size_t plan_out_capacity;

    uint64_t mutation_id;
    char description[128];
} afl_mutator_t;

static uint32_t afl_rng_below(void *context, uint32_t limit) {
    if (limit == 0) return 0u;
    return rand_below((afl_state_t *)context, limit);
}

static void *afl_plan_buf_realloc(afl_mutator_t *mutator, size_t needed) {
    if (!mutator || needed == 0) return NULL;
    if (mutator->plan_out_capacity >= needed) return mutator->plan_out_buf;

    void *next = afl_realloc((void **)&mutator->plan_out_buf, needed);
    if (next) {
        mutator->plan_out_buf = (uint8_t *)next;
        mutator->plan_out_capacity = needed;
    }
    return next;
}

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    (void)seed;

    afl_mutator_t *mutator = (afl_mutator_t *)calloc(1, sizeof(*mutator));
    if (!mutator) return NULL;

    mutator->afl = afl;
    mutator->plan_out_capacity = 0;
    mutator->plan_out_buf = NULL;
    mutator->mutation_id = 0;
    mutator->description[0] = '\0';

    if (strncmp(CA_ENGINE_NAME, "ca_mutator_growing", 17) == 0) {
        snprintf(mutator->description, sizeof(mutator->description),
                 "Growing CA mutation planner mutator");
    } else {
        snprintf(mutator->description, sizeof(mutator->description),
                 "XOR CA full-buffer baseline mutator");
    }

    ca_engine_config_t config = {
        .user_context = NULL,
    };
    ca_rng_t rng = {
        .below = afl_rng_below,
        .context = afl,
    };

    ca_status_t status =
#if CA_ENGINE_VARIANT == 1
        ca_engine_create_xor(&config, rng, &mutator->engine);
#else
        ca_engine_create_growing(&config, rng, &mutator->engine);
#endif

    if (status != CA_STATUS_OK || !mutator->engine) {
        free(mutator);
        return NULL;
    }

    return mutator;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                      uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
    (void)add_buf;
    (void)add_buf_size;

    afl_mutator_t *mutator = (afl_mutator_t *)data;
    if (!mutator || !buf || !out_buf) return 0;
    *out_buf = NULL;

    ca_mutate_request_t request = {
        .input = buf,
        .input_len = buf_size,
        .add_buf = NULL,
        .add_buf_len = 0,
        .max_output_len = max_size,
        .mutation_id = mutator->mutation_id++,
    };

    ca_output_t output = {0};
    ca_status_t status = ca_engine_mutate(mutator->engine, &request, &output);
    if (status == CA_STATUS_SKIP || status == CA_STATUS_OUTPUT_TOO_LARGE) {
        *out_buf = NULL;
        return 0;
    }
    if (status != CA_STATUS_OK) {
        *out_buf = NULL;
        return 0;
    }

    if (output.kind == CA_OUTPUT_BUFFER) {
        if (!output.value.buffer.data) return 0;
        if (max_size != 0 && output.value.buffer.len > max_size) return 0;
        if (output.value.buffer.len == 0) return 0;
        *out_buf = (uint8_t *)output.value.buffer.data;
        return output.value.buffer.len;
    }

    if (output.kind != CA_OUTPUT_PLAN || !output.value.plan) {
        *out_buf = NULL;
        return 0;
    }

    ca_plan_limits_t limits = {
        .max_ops = 0,
        .max_output_len = max_size,
        .input_len = buf_size,
        .input = buf,
    };

    normalized_plan_t normalized = {0};
    status = mutation_plan_normalize(output.value.plan, &limits, &normalized);
    if (status == CA_STATUS_SKIP || status == CA_STATUS_OUTPUT_TOO_LARGE) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }
    if (status != CA_STATUS_OK) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }

    if (normalized.op_count == 0) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }

    size_t out_size = 0;
    status = mutation_plan_measure(&normalized, buf_size, &out_size);
    if (status == CA_STATUS_SKIP || status == CA_STATUS_OUTPUT_TOO_LARGE) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }
    if (status != CA_STATUS_OK) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }
    if (out_size == 0) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }
    if (out_size > max_size) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }

    void *buffer = afl_plan_buf_realloc(mutator, out_size);
    if (!buffer) {
        normalized_plan_free(&normalized);
        *out_buf = NULL;
        return 0;
    }

    size_t written = 0;
    status = mutation_plan_apply(&normalized, buf, buf_size, mutator->plan_out_buf,
                                mutator->plan_out_capacity, &written);
    normalized_plan_free(&normalized);
    if (status != CA_STATUS_OK || written != out_size || written > max_size) {
        *out_buf = NULL;
        return 0;
    }

    if (written == buf_size &&
        (written == 0 || memcmp(mutator->plan_out_buf, buf, written) == 0)) {
        *out_buf = NULL;
        return 0;
    }

    *out_buf = mutator->plan_out_buf;
    return written;
}

const char *afl_custom_describe(void *data, size_t max_description_len) {
    afl_mutator_t *mutator = (afl_mutator_t *)data;
    if (!mutator || max_description_len == 0) {
        return "ca-mutator";
    }

    size_t len = strlen(mutator->description);
    if (len >= max_description_len) {
        mutator->description[max_description_len - 1] = '\0';
    }
    return mutator->description;
}

void afl_custom_splice_optout(void *data) {
    (void)data;
}

void afl_custom_deinit(void *data) {
    afl_mutator_t *mutator = (afl_mutator_t *)data;
    if (!mutator) return;

    ca_engine_destroy(mutator->engine);
    if (mutator->plan_out_buf) {
        afl_free(mutator->plan_out_buf);
    }
    free(mutator);
}
