#ifndef CA_MUTATOR_MUTATION_PLAN_H_
#define CA_MUTATOR_MUTATION_PLAN_H_

#include <stddef.h>
#include <stdint.h>

#include "ca_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CA_OP_BIT_FLIP = 1,
    CA_OP_SET_BYTE = 2,
    CA_OP_ADD_BYTE = 3,
    CA_OP_SUB_BYTE = 4,
    CA_OP_DELETE_RANGE = 5,
    CA_OP_INSERT_BYTES = 6,
} mutation_op_kind_t;

typedef struct {
    mutation_op_kind_t kind;
    uint32_t pos;
    uint32_t len;
    uint32_t score;
    uint32_t source_index;
    union {
        struct {
            uint8_t bit_index;
        } bit_flip;
        struct {
            uint8_t value;
        } set_byte;
        struct {
            uint8_t delta;
        } arithmetic;
        struct {
            const uint8_t *data;
            size_t data_len;
        } insert;
    } arg;
    size_t data_offset;
} mutation_op_t;

typedef struct mutation_plan {
    mutation_op_t *ops;
    size_t op_count;
    uint8_t *extra_bytes;
    size_t extra_bytes_len;
} mutation_plan_t;

typedef mutation_plan_t normalized_plan_t;

typedef struct {
    size_t max_ops;
    size_t max_output_len;
    size_t input_len;
    const uint8_t *input;
} ca_plan_limits_t;

ca_status_t mutation_plan_init(mutation_plan_t *plan);
ca_status_t mutation_plan_add_bit_flip(mutation_plan_t *plan, uint32_t pos,
                                      uint8_t bit_mask, uint32_t score,
                                      uint32_t source_index);
ca_status_t mutation_plan_add_set_byte(mutation_plan_t *plan, uint32_t pos,
                                      uint8_t value, uint32_t score,
                                      uint32_t source_index);
ca_status_t mutation_plan_add_add_byte(mutation_plan_t *plan, uint32_t pos,
                                      int8_t delta, uint32_t score,
                                      uint32_t source_index);
ca_status_t mutation_plan_add_sub_byte(mutation_plan_t *plan, uint32_t pos,
                                      int8_t delta, uint32_t score,
                                      uint32_t source_index);
ca_status_t mutation_plan_add_delete_range(mutation_plan_t *plan, uint32_t pos,
                                         uint32_t len, uint32_t score,
                                         uint32_t source_index);
ca_status_t mutation_plan_add_insert_bytes(mutation_plan_t *plan, uint32_t pos,
                                          const uint8_t *data, uint32_t len,
                                          uint32_t score,
                                          uint32_t source_index);
void mutation_plan_destroy(mutation_plan_t *plan);

void normalized_plan_free(normalized_plan_t *plan);
ca_status_t mutation_plan_normalize(const mutation_plan_t *source,
                                   const ca_plan_limits_t *limits,
                                   normalized_plan_t *result);
ca_status_t mutation_plan_measure(const normalized_plan_t *plan, size_t input_len,
                                 size_t *output_len);
ca_status_t mutation_plan_apply(const normalized_plan_t *plan, const uint8_t *input,
                               size_t input_len, uint8_t *output,
                               size_t output_capacity, size_t *output_len);

#ifdef __cplusplus
}
#endif

#endif  // CA_MUTATOR_MUTATION_PLAN_H_
