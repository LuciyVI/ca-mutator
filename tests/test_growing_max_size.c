#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ca_engine.h"
#include "table_rng.h"
#include "growing_test_support.h"

static const uint32_t kMaxSizeSeq[] = {
    11, 5, 17, 2, 23, 7, 29, 1, 4, 26, 12, 16, 18, 31, 3, 9,
};

static int check_case(ca_engine_t *engine, const uint8_t *input, size_t input_len,
                      size_t max_size, size_t mutation_id) {
    grow_result_t r = {0};
    if (!grow_mutate_to_owned_buffer(engine, input, input_len, max_size, mutation_id,
                                    &r)) {
        return 0;
    }

    if (r.len > max_size) {
        fprintf(stderr, "max_size violated: out=%zu max=%zu\n", r.len, max_size);
        grow_result_free(&r);
        return 0;
    }

    if (!r.is_skip && max_size == 0) {
        fprintf(stderr, "non-skip when max_size=0\n");
        grow_result_free(&r);
        return 0;
    }

    if (!r.is_skip && r.len == input_len && input_len != 0 &&
        memcmp(r.data, input, input_len) == 0) {
        fprintf(stderr, "no-op success when max_size=%zu input_len=%zu\n", max_size,
                input_len);
        grow_result_free(&r);
        return 0;
    }

    grow_result_free(&r);
    return 1;
}

int main(void) {
    table_rng_state_t rng = {0};
    table_rng_init(&rng, kMaxSizeSeq, sizeof(kMaxSizeSeq) / sizeof(*kMaxSizeSeq));
    ca_rng_t rnd = {.below = table_rng_below, .context = &rng};

    ca_engine_t *engine = NULL;
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd,
                                &engine) != CA_STATUS_OK) {
        return 1;
    }

    static const uint8_t case1[] = {0x42};
    static const uint8_t case2[] = "growing max size text";
    static const uint8_t case3[] = {[0 ... 255] = 0xAA};

    bool ok = true;

    ok &= check_case(engine, case1, 0, 0, 0);
    ok &= check_case(engine, case1, sizeof(case1), 0, 100);
    ok &= check_case(engine, case1, 0, 1, 1);
    ok &= check_case(engine, case2, sizeof(case2), 1, 2);
    ok &= check_case(engine, case2, sizeof(case2), sizeof(case2) - 1, 3);
    ok &= check_case(engine, case2, sizeof(case2), sizeof(case2), 4);
    ok &= check_case(engine, case2, sizeof(case2), sizeof(case2) + 128, 5);
    ok &= check_case(engine, case3, sizeof(case3), sizeof(case3) - 2, 6);
    ok &= check_case(engine, case3, sizeof(case3), sizeof(case3) + 1000, 7);

    if (!ok) {
        ca_engine_destroy(engine);
        return 1;
    }

    for (size_t iter = 0; iter < 100; ++iter) {
        size_t max_size = 1 + (iter % 16);
        if (!check_case(engine, case3, sizeof(case3), max_size,
                       1000 + iter)) {
            ok = false;
            break;
        }
    }

    ca_engine_destroy(engine);
    if (!ok) {
        return 1;
    }

    printf("growing max-size test: PASS\n");
    return 0;
}
