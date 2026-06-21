#include <stdlib.h>

#include "ca_engine_internal.h"

#ifndef CA_ENGINE_VARIANT
#define CA_ENGINE_VARIANT 0
#endif

#if CA_ENGINE_VARIANT == 1 || CA_ENGINE_VARIANT == 0
#include "xor_engine.h"
#endif

#if CA_ENGINE_VARIANT == 2 || CA_ENGINE_VARIANT == 0
#include "growing_engine.h"
#endif

#if CA_ENGINE_VARIANT == 1 || CA_ENGINE_VARIANT == 0
ca_status_t ca_engine_create_xor(const ca_engine_config_t *config, ca_rng_t rng,
                                 ca_engine_t **engine) {
    if (!engine) return CA_STATUS_INVALID_ARGUMENT;
    return ca_engine_create_xor_impl(config, rng, engine);
}
#endif

#if CA_ENGINE_VARIANT == 2 || CA_ENGINE_VARIANT == 0
ca_status_t ca_engine_create_growing(const ca_engine_config_t *config, ca_rng_t rng,
                                     ca_engine_t **engine) {
    if (!engine) return CA_STATUS_INVALID_ARGUMENT;
    return ca_engine_create_growing_impl(config, rng, engine);
}
#endif

ca_status_t ca_engine_mutate(ca_engine_t *engine,
                            const ca_mutate_request_t *request,
                            ca_output_t *output) {
    if (!engine || !request || !output) return CA_STATUS_INVALID_ARGUMENT;
    return engine->mutate(engine->impl, request, output);
}

void ca_engine_destroy(ca_engine_t *engine) {
    if (!engine) return;
    if (engine->destroy) {
        engine->destroy(engine->impl);
    }
    free(engine);
}
