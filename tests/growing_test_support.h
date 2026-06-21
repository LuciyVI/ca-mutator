#ifndef CA_MUTATOR_GROWING_TEST_SUPPORT_H_
#define CA_MUTATOR_GROWING_TEST_SUPPORT_H_

#include <stddef.h>
#include <stdint.h>

#include "ca_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int is_skip;
    ca_status_t status;
    size_t len;
    uint8_t *data;
} grow_result_t;

uint64_t grow_hash64(const uint8_t *data, size_t len);

int grow_mutate_to_owned_buffer(ca_engine_t *engine, const uint8_t *input,
                               size_t input_len, size_t max_output_len,
                               uint64_t mutation_id, grow_result_t *result);

void grow_result_free(grow_result_t *result);

#ifdef __cplusplus
}
#endif

#endif  // CA_MUTATOR_GROWING_TEST_SUPPORT_H_
