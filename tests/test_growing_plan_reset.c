#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ca_engine.h"
#include "table_rng.h"
#include "growing_test_support.h"

static const uint32_t kResetSeq[] = {
    9, 12, 15, 3, 28, 7, 22, 1, 31, 8, 14, 5, 17, 24, 2, 11,
};

int main(void) {
    table_rng_state_t rng = {0};
    table_rng_init(&rng, kResetSeq, sizeof(kResetSeq) / sizeof(*kResetSeq));
    ca_rng_t rnd = {.below = table_rng_below, .context = &rng};

    ca_engine_t *engine = NULL;
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd,
                                &engine) != CA_STATUS_OK) {
        return 1;
    }

    const uint8_t in_a[] = {0x01, 0x02, 0x03};
    const uint8_t in_b[] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5};

    bool ok = true;
    grow_result_t a = {0};
    grow_result_t b = {0};

    for (size_t i = 0; i < 2000; ++i) {
        if (!grow_mutate_to_owned_buffer(engine, in_a, sizeof(in_a), 8192,
                                        (uint64_t)(i * 2 + 1), &a) ||
            !grow_mutate_to_owned_buffer(engine, in_b, sizeof(in_b), 8192,
                                        (uint64_t)(i * 2 + 2), &b)) {
            ok = false;
            fprintf(stderr, "invoke failed at iteration %zu\n", i);
            grow_result_free(&a);
            grow_result_free(&b);
            break;
        }

        if (!a.is_skip && !b.is_skip && a.len == b.len && a.len != 0 &&
            memcmp(a.data, b.data, a.len) == 0) {
            fprintf(stderr,
                    "suspicious equal output after input switch at iteration %zu\n",
                    i);
            ok = false;
        }

        grow_result_free(&a);
        grow_result_free(&b);
        if (!ok) break;
    }

    ca_engine_destroy(engine);
    if (!ok) return 1;

    printf("growing plan reset test: PASS\n");
    return 0;
}
