#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ca_engine.h"
#include "table_rng.h"
#include "growing_test_support.h"

static const uint32_t kNoopSeq[] = {
    9, 1, 4, 7, 8, 12, 15, 3, 25, 2, 19, 6, 11, 17, 21, 30,
};

int main(void) {
    table_rng_state_t rng = {0};
    table_rng_init(&rng, kNoopSeq, sizeof(kNoopSeq) / sizeof(*kNoopSeq));
    ca_rng_t rnd = {.below = table_rng_below, .context = &rng};

    ca_engine_t *engine = NULL;
    if (ca_engine_create_growing(&(ca_engine_config_t){.user_context = NULL}, rnd,
                                &engine) != CA_STATUS_OK) {
        return 1;
    }

    const uint8_t case_one[] = {0x00};
    const uint8_t case_ff[] = {0xFF};
    const uint8_t case_text[] = "hello growing no-op check";

    bool ok = true;

    grow_result_t r = {0};
    ok &= grow_mutate_to_owned_buffer(engine, NULL, 0, 1024, 0, &r);
    if (!ok) {
        grow_result_free(&r);
        ca_engine_destroy(engine);
        return 1;
    }
    if (!r.is_skip && r.len == 0) {
        fprintf(stderr, "empty input returned zero length\n");
        ok = false;
    }
    grow_result_free(&r);

    ok &= grow_mutate_to_owned_buffer(engine, case_one, sizeof(case_one), 1024, 1, &r);
    if (!ok) {
        grow_result_free(&r);
        ca_engine_destroy(engine);
        return 1;
    }
    if (!r.is_skip && r.len == sizeof(case_one) && r.data &&
        r.data[0] == case_one[0]) {
        fprintf(stderr, "input 1-byte 0 became no-op\n");
        ok = false;
    }
    grow_result_free(&r);

    ok &= grow_mutate_to_owned_buffer(engine, case_ff, sizeof(case_ff), 1024, 2, &r);
    if (!ok) {
        grow_result_free(&r);
        ca_engine_destroy(engine);
        return 1;
    }
    if (!r.is_skip && r.len == sizeof(case_ff) && r.data &&
        r.data[0] == case_ff[0]) {
        fprintf(stderr, "input 1-byte FF became no-op\n");
        ok = false;
    }
    grow_result_free(&r);

    ok &= grow_mutate_to_owned_buffer(engine, case_text, sizeof(case_text), 1024, 3,
                                      &r);
    if (!ok) {
        grow_result_free(&r);
        ca_engine_destroy(engine);
        return 1;
    }
    if (!r.is_skip && r.len == sizeof(case_text) && r.data &&
        memcmp(r.data, case_text, r.len) == 0) {
        fprintf(stderr, "text input became no-op\n");
        ok = false;
    }
    grow_result_free(&r);

    ca_engine_destroy(engine);
    if (!ok) return 1;

    printf("growing no-op test: PASS\n");
    return 0;
}
