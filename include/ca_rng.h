#ifndef CA_MUTATOR_CA_RNG_H_
#define CA_MUTATOR_CA_RNG_H_

#include <stdint.h>

typedef uint32_t (*ca_rand_below_fn)(void *context, uint32_t upper_bound);

typedef struct {
    // Caller must provide a state context that outlives the engine.
    // `upper_bound` must be > 0 and implementation should return value in [0, upper_bound).
    ca_rand_below_fn below;
    void *context;
} ca_rng_t;

#endif  // CA_MUTATOR_CA_RNG_H_
