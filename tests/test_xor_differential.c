#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ca_engine.h"
#include "legacy_xor_reference.h"
#include "table_rng.h"

static const uint32_t kRngSequence[] = {
    1, 7, 11, 3, 4, 8, 2, 6, 9, 10, 12, 14, 15, 16, 0, 5,
    13, 1, 4, 8, 12, 16, 3, 7, 11, 5, 2, 9, 10, 14, 15, 6,
};

static bool check_case(const uint8_t *input, size_t input_len,
                      size_t max_output_len, size_t calls, const uint32_t *seed,
                      size_t seed_len) {
    table_rng_state_t ref_rng;
    table_rng_state_t eng_rng;
    table_rng_init(&ref_rng, seed, seed_len);
    table_rng_init(&eng_rng, seed, seed_len);

    ca_rng_t rng = {
        .below = table_rng_below,
        .context = &eng_rng,
    };

    ca_engine_t *engine = NULL;
    if (ca_engine_create_xor(&(ca_engine_config_t){.user_context = NULL}, rng,
                            &engine) != CA_STATUS_OK) {
        return false;
    }

    size_t max_in = 4096;
    uint8_t *ref_in = (uint8_t *)malloc(max_in);
    uint8_t *mut_in = (uint8_t *)malloc(max_in);
    uint8_t *ref_out = (uint8_t *)malloc(max_in);
    uint8_t *mut_out = (uint8_t *)malloc(max_in);
    if (!ref_in || !mut_in || !ref_out || !mut_out) {
        free(ref_in);
        free(mut_in);
        free(ref_out);
        free(mut_out);
        ca_engine_destroy(engine);
        return false;
    }

    if (input_len > max_in) {
        free(ref_in);
        free(mut_in);
        free(ref_out);
        free(mut_out);
        ca_engine_destroy(engine);
        return false;
    }

    if (input_len > 0) {
        memcpy(ref_in, input, input_len);
        memcpy(mut_in, input, input_len);
    }

    bool ok = true;
    for (size_t call = 0; call < calls; ++call) {
        size_t ref_out_len = 0;
        size_t mut_out_len = 0;

        ca_status_t ref_status = legacy_xor_mutate_reference(
            ref_in, input_len, max_output_len, table_rng_below, &ref_rng, ref_out,
            max_in, &ref_out_len);

        ca_mutate_request_t request = {
            .input = mut_in,
            .input_len = input_len,
            .add_buf = NULL,
            .add_buf_len = 0,
            .max_output_len = max_output_len,
            .mutation_id = call,
        };

        ca_output_t output = {0};
        ca_status_t eng_status = ca_engine_mutate(engine, &request, &output);

        if (eng_status != ref_status) {
            fprintf(stderr, "status mismatch at call=%zu: ref=%d eng=%d\n", call,
                    (int)ref_status, (int)eng_status);
            ok = false;
            break;
        }

        if (eng_status != CA_STATUS_OK) {
            continue;
        }

        if (output.kind != CA_OUTPUT_BUFFER || !output.value.buffer.data) {
            fprintf(stderr, "engine output kind mismatch\n");
            ok = false;
            break;
        }

        mut_out_len = output.value.buffer.len;
        if (mut_out_len > max_in) {
            fprintf(stderr, "engine output oversized: %zu\n", mut_out_len);
            ok = false;
            break;
        }

        memcpy(mut_out, output.value.buffer.data, mut_out_len);

        if (mut_out_len != ref_out_len || memcmp(ref_out, mut_out, mut_out_len) != 0) {
            fprintf(stderr, "mismatch at call=%zu: ref_len=%zu eng_len=%zu\n", call,
                    ref_out_len, mut_out_len);
            ok = false;
            break;
        }

        if (call + 1 < calls) {
            input_len = mut_out_len;
            if (input_len > 0) {
                memcpy(ref_in, ref_out, input_len);
                memcpy(mut_in, mut_out, input_len);
            }
        }
    }

    free(ref_in);
    free(mut_in);
    free(ref_out);
    free(mut_out);
    ca_engine_destroy(engine);
    return ok;
}

int main(void) {
    const uint32_t *seed = kRngSequence;
    const size_t seed_len = sizeof(kRngSequence) / sizeof(kRngSequence[0]);

    const uint8_t *case_0 = NULL;
    const uint8_t case_1[] = {0x42};
    const uint8_t case_255[] = { [0 ... 254] = 0xAA };
    const uint8_t case_256[] = { [0 ... 255] = 0x55 };
    const uint8_t case_257[] = { [0 ... 256] = 0x5A };

    const uint8_t sequential_seed[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    };

    bool ok = true;

    ok &= check_case(case_0, 0, 1024, 4, seed, seed_len);
    ok &= check_case(case_1, sizeof(case_1), 1024, 4, seed, seed_len);
    ok &= check_case(case_255, sizeof(case_255), 1024, 4, seed, seed_len);
    ok &= check_case(case_256, sizeof(case_256), 1024, 3, seed, seed_len);
    ok &= check_case(case_257, sizeof(case_257), 1024, 3, seed, seed_len);

    ok &= check_case(sequential_seed, sizeof(sequential_seed), 4096, 8, seed,
                     seed_len);

    if (!ok) {
        return 1;
    }

    printf("xor differential test: PASS\n");
    return 0;
}
