#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ca_engine_internal.h"
#include "xor_engine.h"

#define CA_XOR_MAX_WIDTH 256

typedef struct {
    uint8_t *cur;
    uint8_t *next;
    size_t capacity;
    ca_rng_t rng;
    ca_buffer_view_t last_output;
} ca_xor_engine_t;

static uint32_t ca_xor_rand_below(ca_xor_engine_t *engine, uint32_t limit) {
    if (limit == 0) return 0u;
    return engine->rng.below(engine->rng.context, limit);
}

static ca_status_t ca_xor_destroy(void *impl) {
    ca_xor_engine_t *engine = (ca_xor_engine_t *)impl;
    if (!engine) return CA_STATUS_OK;
    free(engine->cur);
    free(engine->next);
    free(engine);
    return CA_STATUS_OK;
}

static ca_status_t ca_xor_ensure_capacity(ca_xor_engine_t *engine, size_t need) {
    if (need == 0 || !engine) return CA_STATUS_INVALID_ARGUMENT;
    if (engine->capacity >= need && engine->cur && engine->next) return CA_STATUS_OK;

    uint8_t *next_cur = (uint8_t *)malloc(need);
    uint8_t *next_next = (uint8_t *)malloc(need);
    if (!next_cur || !next_next) {
        free(next_cur);
        free(next_next);
        return CA_STATUS_OUT_OF_MEMORY;
    }

    free(engine->cur);
    free(engine->next);
    engine->cur = next_cur;
    engine->next = next_next;
    engine->capacity = need;

    return CA_STATUS_OK;
}

static ca_status_t ca_xor_mutate(void *impl,
                                const ca_mutate_request_t *request,
                                ca_output_t *output) {
    ca_xor_engine_t *engine = (ca_xor_engine_t *)impl;
    if (!engine || !request || !output) return CA_STATUS_INVALID_ARGUMENT;
    if (!request->input && request->input_len != 0) return CA_STATUS_INVALID_ARGUMENT;
    if (!engine->rng.below) return CA_STATUS_INVALID_ARGUMENT;

    const uint8_t *input = request->input;
    size_t input_len = request->input_len;
    size_t max_output_len = request->max_output_len;

    if (input_len == 0) {
        if (ca_xor_ensure_capacity(engine, 1) != CA_STATUS_OK) {
            return CA_STATUS_OUT_OF_MEMORY;
        }
        engine->cur[0] = (uint8_t)ca_xor_rand_below(engine, 256u);
        engine->last_output.data = engine->cur;
        engine->last_output.len = 1;
        output->kind = CA_OUTPUT_BUFFER;
        output->value.buffer = engine->last_output;
        return CA_STATUS_OK;
    }

    size_t width = CA_XOR_MAX_WIDTH;
    if (width > input_len) {
        width = input_len;
    }
    if (width == 0) width = 1;

    size_t height = (input_len + width - 1u) / width;
    if (height == 0) height = 1;

    size_t total_cells = width * height;
    if (total_cells < input_len) total_cells = input_len;
    if (total_cells == 0) total_cells = 1;

    if (total_cells > SIZE_MAX / 2) return CA_STATUS_OUT_OF_MEMORY;

    if (ca_xor_ensure_capacity(engine, total_cells) != CA_STATUS_OK) {
        return CA_STATUS_OUT_OF_MEMORY;
    }

    if (input_len > 0 && input) {
        memcpy(engine->cur, input, input_len);
        if (total_cells > input_len) {
            memset(engine->cur + input_len, 0, total_cells - input_len);
        }
    } else if (total_cells > 0) {
        memset(engine->cur, 0, total_cells);
    }

    uint32_t iterations = 1u + ca_xor_rand_below(engine, 8);

    for (uint32_t iter = 0; iter < iterations; ++iter) {
        for (size_t row = 0; row < height; ++row) {
            for (size_t col = 0; col < width; ++col) {
                size_t idx = row * width + col;

                if (ca_xor_rand_below(engine, 4) == 0) {
                    uint8_t bit = (uint8_t)(1u << ca_xor_rand_below(engine, 8));
                    engine->next[idx] = (uint8_t)(engine->cur[idx] ^ bit);
                    continue;
                }

                uint8_t xor_sum = 0;
                for (int dr = -1; dr <= 1; ++dr) {
                    for (int dc = -1; dc <= 1; ++dc) {
                        if (dr == 0 && dc == 0) continue;
                        int r = (int)row + dr;
                        if (r < 0) {
                            r += (int)height;
                        } else if ((size_t)r >= height) {
                            r -= (int)height;
                        }
                        int c = (int)col + dc;
                        if (c < 0) {
                            c += (int)width;
                        } else if ((size_t)c >= width) {
                            c -= (int)width;
                        }
                        xor_sum ^= engine->cur[(size_t)r * width + (size_t)c];
                    }
                }
                engine->next[idx] = xor_sum;
            }
        }

        uint8_t *tmp = engine->cur;
        engine->cur = engine->next;
        engine->next = tmp;
    }

    size_t out_len = total_cells;
    if (max_output_len != 0 && out_len > max_output_len) {
        out_len = max_output_len;
    }

    engine->last_output.data = engine->cur;
    engine->last_output.len = out_len;

    output->kind = CA_OUTPUT_BUFFER;
    output->value.buffer = engine->last_output;
    return CA_STATUS_OK;
}

ca_status_t ca_engine_create_xor_impl(const ca_engine_config_t *config, ca_rng_t rng,
                                      ca_engine_t **engine) {
    if (!engine) return CA_STATUS_INVALID_ARGUMENT;
    (void)config;
    if (!rng.below) return CA_STATUS_INVALID_ARGUMENT;

    ca_xor_engine_t *impl = (ca_xor_engine_t *)calloc(1, sizeof(*impl));
    if (!impl) return CA_STATUS_OUT_OF_MEMORY;
    impl->rng = rng;
    impl->capacity = 0;

    ca_engine_t *base = (ca_engine_t *)malloc(sizeof(*base));
    if (!base) {
        free(impl);
        return CA_STATUS_OUT_OF_MEMORY;
    }

    base->impl = impl;
    base->rng = rng;
    base->output_kind = CA_OUTPUT_BUFFER;
    base->destroy = ca_xor_destroy;
    base->mutate = ca_xor_mutate;

    *engine = base;
    return CA_STATUS_OK;
}
