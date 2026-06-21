#ifndef CA_MUTATOR_TEST_TABLE_RNG_H_
#define CA_MUTATOR_TEST_TABLE_RNG_H_

#include <stddef.h>
#include <stdint.h>

#include "ca_rng.h"

typedef struct {
    const uint32_t *values;
    size_t count;
    size_t next;
} table_rng_state_t;

void table_rng_init(table_rng_state_t *state, const uint32_t *values, size_t count);
uint32_t table_rng_below(void *context, uint32_t upper_bound);

#endif  // CA_MUTATOR_TEST_TABLE_RNG_H_
