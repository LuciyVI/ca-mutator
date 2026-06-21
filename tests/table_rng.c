#include "table_rng.h"

void table_rng_init(table_rng_state_t *state, const uint32_t *values, size_t count) {
    if (!state) return;
    state->values = values;
    state->count = count;
    state->next = 0;
}

uint32_t table_rng_below(void *context, uint32_t upper_bound) {
    table_rng_state_t *state = (table_rng_state_t *)context;
    if (!state || upper_bound == 0 || !state->values || state->count == 0) {
        return 0u;
    }

    uint32_t raw = state->values[state->next % state->count];
    ++state->next;
    return raw % upper_bound;
}
