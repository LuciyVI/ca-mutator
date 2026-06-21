#ifndef CA_MUTATOR_CA_ENGINE_H_
#define CA_MUTATOR_CA_ENGINE_H_

#include <stddef.h>
#include <stdint.h>

#include "ca_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mutation_plan mutation_plan_t;
typedef struct ca_engine ca_engine_t;

typedef struct {
    // Reserved for future engine-local non-crypto context.
    void *user_context;
} ca_engine_config_t;

typedef enum {
    CA_OUTPUT_BUFFER = 1,
    CA_OUTPUT_PLAN = 2,
} ca_output_kind_t;

typedef enum {
    CA_STATUS_OK = 0,
    CA_STATUS_SKIP,
    CA_STATUS_INVALID_ARGUMENT,
    CA_STATUS_OUT_OF_MEMORY,
    CA_STATUS_INTERNAL_ERROR,
    CA_STATUS_OUTPUT_TOO_LARGE,
} ca_status_t;

typedef struct {
    const uint8_t *data;
    size_t len;
} ca_buffer_view_t;

typedef struct {
    const uint8_t *input;
    size_t input_len;

    const uint8_t *add_buf;
    size_t add_buf_len;

    // Passed through from AFL++ `max_size`; 0 is a strict limit of zero output bytes
    // for plan-based engines.
    size_t max_output_len;
    // Reserved for diagnostics in v1 (mutation trace/call index).
    uint64_t mutation_id;
} ca_mutate_request_t;

typedef struct {
    ca_output_kind_t kind;
    union {
        ca_buffer_view_t buffer;
        const mutation_plan_t *plan;
    } value;
} ca_output_t;

ca_status_t ca_engine_create_xor(const ca_engine_config_t *config, ca_rng_t rng,
                                ca_engine_t **engine);
ca_status_t ca_engine_create_growing(const ca_engine_config_t *config, ca_rng_t rng,
                                    ca_engine_t **engine);
ca_status_t ca_engine_mutate(ca_engine_t *engine,
                            const ca_mutate_request_t *request,
                            ca_output_t *output);
void ca_engine_destroy(ca_engine_t *engine);

#ifdef __cplusplus
}
#endif

#endif  // CA_MUTATOR_CA_ENGINE_H_
