#ifndef CA_MUTATOR_CA_ENGINE_INTERNAL_H_
#define CA_MUTATOR_CA_ENGINE_INTERNAL_H_

#include "ca_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ca_status_t (*ca_engine_destroy_fn)(void *impl);
typedef ca_status_t (*ca_engine_mutate_fn)(void *impl,
                                          const ca_mutate_request_t *request,
                                          ca_output_t *output);

struct ca_engine {
    void *impl;
    ca_rng_t rng;
    ca_output_kind_t output_kind;

    ca_engine_destroy_fn destroy;
    ca_engine_mutate_fn mutate;
};

#ifdef __cplusplus
}
#endif

#endif  // CA_MUTATOR_CA_ENGINE_INTERNAL_H_
