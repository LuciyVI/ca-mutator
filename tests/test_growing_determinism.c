#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ca_engine.h"
#include "table_rng.h"
#include "growing_test_support.h"

static const uint32_t kGrowingRngSeq[] = {
    11, 23, 7, 2, 9, 14, 31, 4, 18, 1, 16, 13, 25, 19, 5, 8,
    29, 3, 27, 6, 12, 20, 17, 21, 22, 4, 28, 15, 24, 26, 10, 30,
};

static bool compare_session(const uint8_t *input, size_t input_len, size_t calls) {
    table_rng_state_t rng1 = {0};
    table_rng_state_t rng2 = {0};
    table_rng_init(&rng1, kGrowingRngSeq, sizeof(kGrowingRngSeq) / sizeof(*kGrowingRngSeq));
    table_rng_init(&rng2, kGrowingRngSeq, sizeof(kGrowingRngSeq) / sizeof(*kGrowingRngSeq));

    ca_rng_t rnd1 = {.below = table_rng_below, .context = &rng1};
    ca_rng_t rnd2 = {.below = table_rng_below, .context = &rng2};

    ca_engine_t *engine1 = NULL;
    ca_engine_t *engine2 = NULL;
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd1,
                                &engine1) != CA_STATUS_OK) {
        return false;
    }
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd2,
                                &engine2) != CA_STATUS_OK) {
        ca_engine_destroy(engine1);
        return false;
    }

    bool ok = true;

    for (size_t i = 0; i < calls; ++i) {
        grow_result_t r1 = {0};
        grow_result_t r2 = {0};

        if (!grow_mutate_to_owned_buffer(engine1, input, input_len, 4096,
                                        (uint64_t)i, &r1)) {
            ok = false;
            grow_result_free(&r1);
            grow_result_free(&r2);
            break;
        }

        if (!grow_mutate_to_owned_buffer(engine2, input, input_len, 4096,
                                        (uint64_t)i, &r2)) {
            ok = false;
            grow_result_free(&r1);
            grow_result_free(&r2);
            break;
        }

        if (r1.status != r2.status || r1.is_skip != r2.is_skip ||
            r1.len != r2.len) {
            fprintf(stderr,
                    "mismatch at call=%zu status=%d/%d skip=%d/%d len=%zu/%zu\n",
                    i, (int)r1.status, (int)r2.status, r1.is_skip,
                    r2.is_skip, r1.len, r2.len);
            ok = false;
            grow_result_free(&r1);
            grow_result_free(&r2);
            break;
        }

        if (!r1.is_skip &&
            (r1.len != r2.len || memcmp(r1.data, r2.data, r1.len) != 0)) {
            fprintf(stderr, "bytes mismatch at call=%zu\n", i);
            ok = false;
            grow_result_free(&r1);
            grow_result_free(&r2);
            break;
        }

        if (r1.status != CA_STATUS_OK) {
            grow_result_free(&r1);
            grow_result_free(&r2);
            continue;
        }

        grow_result_free(&r1);
        grow_result_free(&r2);
    }

    ca_engine_destroy(engine1);
    ca_engine_destroy(engine2);
    return ok;
}

int main(void) {
    static const uint8_t case_one[] = {0x00};
    static const uint8_t case_ff[] = {0xFF};
    static const uint8_t case_text[] = "hello growing ca test\n";
    static const uint8_t case_binary1[] = {0x00, 0x10, 0x7F, 0x80, 0xFF};
    static const uint8_t case_binary2[] = {0xA5, 0x5A, 0x00, 0xFF, 0x33};

    const uint8_t *inputs[] = {
        NULL,
        case_one,
        case_ff,
        case_text,
        case_binary1,
        case_binary2,
    };
    const size_t lens[] = {0, 1, 1, sizeof(case_text) - 1, sizeof(case_binary1),
                          sizeof(case_binary2)};
    bool ok = true;

    for (size_t i = 0; i < 2; ++i) {
        ok &= compare_session(inputs[i], lens[i], 5);
    }

    ok &= compare_session(case_text, sizeof(case_text) - 1, 10);
    ok &= compare_session(case_binary1, sizeof(case_binary1), 10);
    ok &= compare_session(case_binary2, sizeof(case_binary2), 10);

    if (!ok) {
        return 1;
    }

    printf("growing determinism test: PASS\n");
    return 0;
}
