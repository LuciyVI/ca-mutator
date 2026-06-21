#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ca_engine.h"
#include "table_rng.h"
#include "growing_test_support.h"

static const uint32_t kReuseRngSeq[] = {
    2, 8, 13, 5, 17, 19, 23, 1, 29, 3, 14, 6, 27, 9, 30, 11,
    24, 4, 26, 16, 20, 22, 18, 25, 7, 10, 12, 15, 31, 21, 28, 0,
};

int main(void) {
    table_rng_state_t rng = {0};
    table_rng_init(&rng, kReuseRngSeq, sizeof(kReuseRngSeq) / sizeof(*kReuseRngSeq));
    ca_rng_t rnd = {.below = table_rng_below, .context = &rng};

    ca_engine_t *engine = NULL;
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd,
                                &engine) != CA_STATUS_OK) {
        return 1;
    }

    static const uint8_t in1[] = {0x12};
    static const uint8_t in255[] = {0xFF};
    static const uint8_t in256[] = { [0 ... 255] = 0xA5 };
    static const uint8_t in257[] = { [0 ... 256] = 0x5A };
    static const uint8_t in4k[] = { [0 ... 4095] = 0x7F };

    const uint8_t *inputs[] = {
        NULL, in1, in255, in256, in257, in4k, in1, NULL,
    };
    const size_t lens[] = {
        0, sizeof(in1), sizeof(in255), sizeof(in256), sizeof(in257),
        sizeof(in4k), sizeof(in1), 0};

    bool ok = true;
    const size_t iterations = 10000;

    for (size_t i = 0; i < iterations; ++i) {
        const size_t idx = i % (sizeof(inputs) / sizeof(inputs[0]));
        const uint8_t *input = inputs[idx];
        const size_t input_len = lens[idx];
        const size_t max_size = (input_len > 0 ? (input_len * 2u) : 1024u);

        grow_result_t r = {0};
        if (!grow_mutate_to_owned_buffer(engine, input, input_len, max_size, i + 1,
                                        &r)) {
            ok = false;
            fprintf(stderr, "invoke failed at iter=%zu\n", i);
            grow_result_free(&r);
            break;
        }

        if (r.is_skip) {
            if (r.data != NULL || r.len != 0) {
                fprintf(stderr, "skip output not nil at iter=%zu\n", i);
                ok = false;
            }
            grow_result_free(&r);
            continue;
        }

        if (r.len == 0) {
            fprintf(stderr, "non-skip empty output at iter=%zu\n", i);
            ok = false;
            grow_result_free(&r);
            break;
        }

        if (r.len > max_size) {
            fprintf(stderr, "output exceeded max_size iter=%zu len=%zu max=%zu\n", i,
                    r.len, max_size);
            ok = false;
            grow_result_free(&r);
            break;
        }

        if (input_len != 0 && r.len == input_len &&
            memcmp(r.data, input, input_len) == 0) {
            fprintf(stderr, "no-op result returned as success iter=%zu\n", i);
            ok = false;
            grow_result_free(&r);
            break;
        }

        grow_result_free(&r);

        if (!ok) break;
    }

    ca_engine_destroy(engine);

    if (!ok) return 1;
    printf("growing reuse test: PASS\n");
    return 0;
}
