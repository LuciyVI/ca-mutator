#include "growing_test_support.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "mutation_plan.h"

uint64_t grow_hash64(const uint8_t *data, size_t len) {
    uint64_t hash = 1469598103934665603ULL;
    const uint64_t prime = 1099511628211ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= (uint64_t)data[i];
        hash *= prime;
    }
    return hash;
}

void grow_result_free(grow_result_t *result) {
    if (!result) return;
    free(result->data);
    result->data = NULL;
    result->len = 0;
    result->is_skip = 1;
}

int grow_mutate_to_owned_buffer(ca_engine_t *engine, const uint8_t *input,
                               size_t input_len, size_t max_output_len,
                               uint64_t mutation_id, grow_result_t *result) {
    if (!engine || !result) return 0;

    result->is_skip = 1;
    result->status = CA_STATUS_OK;
    result->len = 0;
    result->data = NULL;

    if (!input && input_len != 0) {
        result->status = CA_STATUS_INVALID_ARGUMENT;
        return 0;
    }

    ca_mutate_request_t request = {
        .input = input,
        .input_len = input_len,
        .add_buf = NULL,
        .add_buf_len = 0,
        .max_output_len = max_output_len,
        .mutation_id = mutation_id,
    };

    ca_output_t output = {0};
    ca_status_t status = ca_engine_mutate(engine, &request, &output);
    result->status = status;
    if (status == CA_STATUS_SKIP || status == CA_STATUS_OUTPUT_TOO_LARGE) {
        return 1;
    }
    if (status != CA_STATUS_OK) {
        return 0;
    }

    if (output.kind != CA_OUTPUT_PLAN || !output.value.plan) {
        result->status = CA_STATUS_INVALID_ARGUMENT;
        return 0;
    }

    ca_plan_limits_t limits = {
        .max_ops = 0,
        .max_output_len = max_output_len,
        .input_len = input_len,
        .input = input,
    };

    normalized_plan_t normalized = {0};
    status = mutation_plan_normalize(output.value.plan, &limits, &normalized);
    if (status == CA_STATUS_SKIP || status == CA_STATUS_OUTPUT_TOO_LARGE) {
        normalized_plan_free(&normalized);
        return 1;
    }
    if (status != CA_STATUS_OK) {
        normalized_plan_free(&normalized);
        result->status = status;
        return 0;
    }

    if (normalized.op_count == 0) {
        normalized_plan_free(&normalized);
        return 1;
    }

    size_t output_len = 0;
    status = mutation_plan_measure(&normalized, input_len, &output_len);
    if (status != CA_STATUS_OK) {
        normalized_plan_free(&normalized);
        result->status = status;
        return 0;
    }

    if (output_len == 0 || (max_output_len != 0 && output_len > max_output_len)) {
        normalized_plan_free(&normalized);
        return 1;
    }

    uint8_t *buffer = (uint8_t *)malloc(output_len);
    if (!buffer) {
        normalized_plan_free(&normalized);
        result->status = CA_STATUS_OUT_OF_MEMORY;
        return 0;
    }

    size_t written = 0;
    status = mutation_plan_apply(&normalized, input, input_len, buffer, output_len,
                                &written);
    normalized_plan_free(&normalized);
    if (status != CA_STATUS_OK || written != output_len) {
        free(buffer);
        result->status = status;
        return 0;
    }

    if (written == input_len && input_len > 0 &&
        memcmp(buffer, input, input_len) == 0) {
        free(buffer);
        return 1;
    }

    result->is_skip = 0;
    result->len = written;
    result->data = buffer;
    return 1;
}
