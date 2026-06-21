#include "legacy_xor_reference.h"

#include <stdlib.h>
#include <string.h>

#include "ca_rng.h"

ca_status_t legacy_xor_mutate_reference(const uint8_t *input, size_t input_len,
                                       size_t max_output_len, ca_rand_below_fn rand_below,
                                       void *rng_context, uint8_t *out,
                                       size_t out_capacity, size_t *out_len) {
    if (!rand_below || !out_len) {
        return CA_STATUS_INVALID_ARGUMENT;
    }

    if ((input_len != 0 && !input) || (out == NULL && (max_output_len != 0 || out_capacity != 0))) {
        return CA_STATUS_INVALID_ARGUMENT;
    }

    if (input_len == 0) {
        if (out_capacity < 1) {
            return CA_STATUS_OUTPUT_TOO_LARGE;
        }
        *out_len = 1;
        out[0] = (uint8_t)rand_below(rng_context, 256);
        return CA_STATUS_OK;
    }

    size_t width = input_len < 256u ? input_len : 256u;
    if (width == 0) width = 1;

    size_t height = (input_len + width - 1u) / width;
    if (height == 0) height = 1;

    size_t total_cells = width * height;

    uint8_t *cur = (uint8_t *)calloc(total_cells, sizeof(*cur));
    uint8_t *next = (uint8_t *)calloc(total_cells, sizeof(*next));
    if (!cur || !next) {
        free(cur);
        free(next);
        return CA_STATUS_OUT_OF_MEMORY;
    }

    memcpy(cur, input, input_len);
    if (total_cells > input_len) {
        memset(cur + input_len, 0, total_cells - input_len);
    }

    uint32_t iterations = 1u + rand_below(rng_context, 8);
    for (uint32_t iter = 0; iter < iterations; ++iter) {
        for (size_t row = 0; row < height; ++row) {
            for (size_t col = 0; col < width; ++col) {
                size_t idx = row * width + col;
                if (rand_below(rng_context, 4) == 0) {
                    uint8_t bit = (uint8_t)(1u << rand_below(rng_context, 8));
                    next[idx] = (uint8_t)(cur[idx] ^ bit);
                } else {
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
                            xor_sum ^= cur[(size_t)r * width + (size_t)c];
                        }
                    }
                    next[idx] = xor_sum;
                }
            }
        }

        uint8_t *tmp = cur;
        cur = next;
        next = tmp;
    }

    size_t requested = total_cells;
    if (max_output_len != 0 && requested > max_output_len) requested = max_output_len;

    free(next);

    if (requested > out_capacity) {
        free(cur);
        return CA_STATUS_OUTPUT_TOO_LARGE;
    }

    memcpy(out, cur, requested);
    *out_len = requested;
    free(cur);
    return CA_STATUS_OK;
}
