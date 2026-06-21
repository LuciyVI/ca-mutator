#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ca_engine.h"
#include "table_rng.h"
#include "growing_test_support.h"

static const uint32_t kProgressRngSeq[] = {
    3, 17, 24, 6, 9, 11, 30, 1, 14, 22, 5, 8, 13, 27, 2, 4,
    19, 18, 7, 10, 16, 23, 12, 29, 21, 26, 31, 25, 28, 15, 20,
};

int main(void) {
    table_rng_state_t rng1 = {0};
    table_rng_state_t rng2 = {0};
    table_rng_init(&rng1, kProgressRngSeq, sizeof(kProgressRngSeq) / sizeof(*kProgressRngSeq));
    table_rng_init(&rng2, kProgressRngSeq, sizeof(kProgressRngSeq) / sizeof(*kProgressRngSeq));

    ca_rng_t rnd1 = {.below = table_rng_below, .context = &rng1};
    ca_rng_t rnd2 = {.below = table_rng_below, .context = &rng2};

    ca_engine_t *engine1 = NULL;
    ca_engine_t *engine2 = NULL;
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd1,
                                &engine1) != CA_STATUS_OK) {
        return 1;
    }
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd2,
                                &engine2) != CA_STATUS_OK) {
        ca_engine_destroy(engine1);
        return 1;
    }

    const uint8_t input[] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66};
    const size_t input_len = sizeof(input);

    bool ok = true;
    size_t prev1 = rng1.next;
    size_t prev2 = rng2.next;

    for (size_t call = 0; call < 100; ++call) {
        grow_result_t r1 = {0};
        grow_result_t r2 = {0};
        if (!grow_mutate_to_owned_buffer(engine1, input, input_len, 4096,
                                        (uint64_t)call, &r1) ||
            !grow_mutate_to_owned_buffer(engine2, input, input_len, 4096,
                                        (uint64_t)call, &r2)) {
            ok = false;
            grow_result_free(&r1);
            grow_result_free(&r2);
            break;
        }

        if (!(rng1.next > prev1 && rng2.next > prev2)) {
            fprintf(stderr, "RNG state not progressed at call=%zu (%zu->%zu, %zu->%zu)\n",
                    call, prev1, rng1.next, prev2, rng2.next);
            ok = false;
        }

        if (r1.status != r2.status || r1.len != r2.len || r1.is_skip != r2.is_skip) {
            fprintf(stderr, "RNG progress divergence at call=%zu\n", call);
            ok = false;
        }

        if (!r1.is_skip) {
            if (r2.data == NULL || r1.len != r2.len || memcmp(r1.data, r2.data, r1.len) != 0) {
                fprintf(stderr, "Mutation payload divergence at call=%zu\n", call);
                ok = false;
            }
        }

        prev1 = rng1.next;
        prev2 = rng2.next;

        grow_result_free(&r1);
        grow_result_free(&r2);

        if (!ok) break;
    }

    ca_engine_destroy(engine1);
    ca_engine_destroy(engine2);
    if (!ok) return 1;

    printf("growing rng progress test: PASS\n");
    return 0;
}
