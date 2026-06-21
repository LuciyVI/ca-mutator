#ifndef CA_MUTATOR_LEGACY_XOR_REFERENCE_H_
#define CA_MUTATOR_LEGACY_XOR_REFERENCE_H_

#include <stddef.h>
#include <stdint.h>

#include "ca_engine.h"

ca_status_t legacy_xor_mutate_reference(const uint8_t *input,
                                        size_t input_len,
                                        size_t max_output_len,
                                        ca_rand_below_fn rand_below,
                                        void *rng_context,
                                        uint8_t *out,
                                        size_t out_capacity,
                                        size_t *out_len);

#endif  // CA_MUTATOR_LEGACY_XOR_REFERENCE_H_
