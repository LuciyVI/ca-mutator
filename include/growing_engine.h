#ifndef CA_MUTATOR_GROWING_ENGINE_H_
#define CA_MUTATOR_GROWING_ENGINE_H_

#include "ca_engine.h"

ca_status_t ca_engine_create_growing_impl(const ca_engine_config_t *config,
                                         ca_rng_t rng, ca_engine_t **engine);

#endif  // CA_MUTATOR_GROWING_ENGINE_H_
