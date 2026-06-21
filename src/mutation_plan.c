#include "mutation_plan.h"

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool size_add_overflow(size_t a, size_t b, size_t *result) {
    if (result == NULL) return true;
    if (a > SIZE_MAX - b) return true;
    *result = a + b;
    return false;
}

static bool size_sub_underflow(size_t a, size_t b, size_t *result) {
    if (result == NULL) return true;
    if (a < b) return true;
    *result = a - b;
    return false;
}

static ca_status_t append_to_plan(mutation_plan_t *plan, const mutation_plan_t *source,
                                 const mutation_op_t *op) {
    if (!plan || !source || !op) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t copy = *op;
    copy.arg.insert.data = NULL;
    copy.data_offset = 0;

    if (op->kind == CA_OP_INSERT_BYTES) {
        size_t data_len = op->arg.insert.data_len;
        if (data_len == 0 || data_len != op->len) return CA_STATUS_INVALID_ARGUMENT;

        const uint8_t *src_data = op->arg.insert.data;
        const uint8_t *source_payload = source->extra_bytes;
        if (source_payload != NULL && source->extra_bytes_len != 0 &&
            op->data_offset <= source->extra_bytes_len &&
            data_len <= source->extra_bytes_len - op->data_offset &&
            src_data == source_payload + op->data_offset) {
            src_data = source_payload + op->data_offset;
        }

        if (!src_data) return CA_STATUS_INVALID_ARGUMENT;

        size_t new_len = 0;
        if (size_add_overflow(plan->extra_bytes_len, data_len, &new_len)) {
            return CA_STATUS_OUT_OF_MEMORY;
        }

        uint8_t *new_extra = (uint8_t *)realloc(plan->extra_bytes, new_len);
        if (!new_extra && new_len != 0) return CA_STATUS_OUT_OF_MEMORY;

        memcpy(new_extra + plan->extra_bytes_len, src_data, data_len);
        plan->extra_bytes = new_extra;
        copy.data_offset = plan->extra_bytes_len;
        copy.arg.insert.data = new_extra + copy.data_offset;
        plan->extra_bytes_len = new_len;
    }

    mutation_op_t *new_ops =
        (mutation_op_t *)realloc(plan->ops, (plan->op_count + 1) * sizeof(*plan->ops));
    if (!new_ops && (plan->op_count + 1) != 0) return CA_STATUS_OUT_OF_MEMORY;

    plan->ops = new_ops;
    plan->ops[plan->op_count++] = copy;
    return CA_STATUS_OK;
}

ca_status_t mutation_plan_init(mutation_plan_t *plan) {
    if (!plan) return CA_STATUS_INVALID_ARGUMENT;

    plan->ops = NULL;
    plan->op_count = 0;
    plan->extra_bytes = NULL;
    plan->extra_bytes_len = 0;
    return CA_STATUS_OK;
}

void mutation_plan_destroy(mutation_plan_t *plan) {
    if (!plan) return;
    free(plan->ops);
    free(plan->extra_bytes);
    plan->ops = NULL;
    plan->extra_bytes = NULL;
    plan->op_count = 0;
    plan->extra_bytes_len = 0;
}

ca_status_t mutation_plan_add_bit_flip(mutation_plan_t *plan, uint32_t pos,
                                      uint8_t bit_index, uint32_t score,
                                      uint32_t source_index) {
    if (!plan) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t op = {
        .kind = CA_OP_BIT_FLIP,
        .pos = pos,
        .len = 1,
        .arg = {
            .bit_flip = {
                .bit_index = (uint8_t)(bit_index & 7u),
            },
        },
        .score = score,
        .source_index = source_index,
    };
    return append_to_plan(plan, plan, &op);
}

ca_status_t mutation_plan_add_set_byte(mutation_plan_t *plan, uint32_t pos,
                                      uint8_t value, uint32_t score,
                                      uint32_t source_index) {
    if (!plan) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t op = {
        .kind = CA_OP_SET_BYTE,
        .pos = pos,
        .len = 1,
        .arg = {
            .set_byte = {
                .value = value,
            },
        },
        .score = score,
        .source_index = source_index,
    };
    return append_to_plan(plan, plan, &op);
}

ca_status_t mutation_plan_add_add_byte(mutation_plan_t *plan, uint32_t pos,
                                      int8_t delta, uint32_t score,
                                      uint32_t source_index) {
    if (!plan) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t op = {
        .kind = CA_OP_ADD_BYTE,
        .pos = pos,
        .len = 1,
        .arg = {
            .arithmetic = {
                .delta = (uint8_t)delta,
            },
        },
        .score = score,
        .source_index = source_index,
    };
    return append_to_plan(plan, plan, &op);
}

ca_status_t mutation_plan_add_sub_byte(mutation_plan_t *plan, uint32_t pos,
                                      int8_t delta, uint32_t score,
                                      uint32_t source_index) {
    if (!plan) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t op = {
        .kind = CA_OP_SUB_BYTE,
        .pos = pos,
        .len = 1,
        .arg = {
            .arithmetic = {
                .delta = (uint8_t)delta,
            },
        },
        .score = score,
        .source_index = source_index,
    };
    return append_to_plan(plan, plan, &op);
}

ca_status_t mutation_plan_add_delete_range(mutation_plan_t *plan, uint32_t pos,
                                          uint32_t len, uint32_t score,
                                          uint32_t source_index) {
    if (!plan) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t op = {
        .kind = CA_OP_DELETE_RANGE,
        .pos = pos,
        .len = len,
        .score = score,
        .source_index = source_index,
    };
    return append_to_plan(plan, plan, &op);
}

ca_status_t mutation_plan_add_insert_bytes(mutation_plan_t *plan, uint32_t pos,
                                          const uint8_t *data, uint32_t len,
                                          uint32_t score, uint32_t source_index) {
    if (!plan || !data || len == 0) return CA_STATUS_INVALID_ARGUMENT;

    mutation_op_t op = {
        .kind = CA_OP_INSERT_BYTES,
        .pos = pos,
        .len = len,
        .arg = {
            .insert = {
                .data = data,
                .data_len = len,
            },
        },
        .score = score,
        .source_index = source_index,
        .data_offset = 0,
    };
    return append_to_plan(plan, plan, &op);
}

void normalized_plan_free(normalized_plan_t *plan) {
    if (!plan) return;
    free(plan->ops);
    free(plan->extra_bytes);
    plan->ops = NULL;
    plan->extra_bytes = NULL;
    plan->op_count = 0;
    plan->extra_bytes_len = 0;
}

static bool op_is_point(const mutation_op_t *op) {
    return op->kind == CA_OP_BIT_FLIP || op->kind == CA_OP_SET_BYTE ||
           op->kind == CA_OP_ADD_BYTE || op->kind == CA_OP_SUB_BYTE;
}

static bool op_is_supported(const mutation_op_t *op) {
    if (!op) return false;
    if (op_is_point(op)) return true;
    return op->kind == CA_OP_DELETE_RANGE || op->kind == CA_OP_INSERT_BYTES;
}

static bool delete_contains_pos(const mutation_op_t *del, uint32_t pos) {
    if (!del || del->kind != CA_OP_DELETE_RANGE || del->len == 0) return false;

    uint64_t end = (uint64_t)del->pos + (uint64_t)del->len;
    if (end > UINT32_MAX) return false;

    return pos >= del->pos && (uint64_t)pos < end;
}

static bool ranges_overlap(uint32_t a_pos, uint32_t a_len, uint32_t b_pos, uint32_t b_len) {
    uint64_t a_end = (uint64_t)a_pos + (uint64_t)a_len;
    uint64_t b_end = (uint64_t)b_pos + (uint64_t)b_len;
    return (uint64_t)a_pos < b_end && (uint64_t)b_pos < a_end;
}

static int cmp_score(const void *left, const void *right) {
    const mutation_op_t *a = (const mutation_op_t *)left;
    const mutation_op_t *b = (const mutation_op_t *)right;
    if (a->score != b->score) return (a->score < b->score) ? 1 : -1;
    if (a->source_index != b->source_index) {
        return (a->source_index < b->source_index) ? -1 : 1;
    }
    return 0;
}

static int cmp_pos_then_source(const void *left, const void *right) {
    const mutation_op_t *a = (const mutation_op_t *)left;
    const mutation_op_t *b = (const mutation_op_t *)right;
    if (a->pos != b->pos) return (a->pos < b->pos) ? -1 : 1;
    if (a->source_index != b->source_index) {
        return (a->source_index < b->source_index) ? -1 : 1;
    }
    return 0;
}

static bool op_conflicts(const mutation_op_t *candidate,
                        const normalized_plan_t *accepted) {
    for (size_t i = 0; i < accepted->op_count; ++i) {
        const mutation_op_t *cur = &accepted->ops[i];

        if (candidate->kind == CA_OP_INSERT_BYTES && cur->kind == CA_OP_INSERT_BYTES &&
            cur->pos == candidate->pos) {
            return true;
        }

        if (op_is_point(candidate) && op_is_point(cur) && candidate->pos == cur->pos) {
            return true;
        }

        if (candidate->kind == CA_OP_DELETE_RANGE &&
            cur->kind == CA_OP_DELETE_RANGE &&
            ranges_overlap(candidate->pos, candidate->len, cur->pos, cur->len)) {
            return true;
        }

        if (candidate->kind == CA_OP_DELETE_RANGE &&
            cur->kind != CA_OP_DELETE_RANGE && delete_contains_pos(cur, candidate->pos)) {
            return true;
        }

        if (candidate->kind != CA_OP_DELETE_RANGE && cur->kind == CA_OP_DELETE_RANGE &&
            delete_contains_pos(cur, candidate->pos)) {
            return true;
        }

        if (candidate->kind == CA_OP_INSERT_BYTES && cur->kind == CA_OP_DELETE_RANGE &&
            candidate->pos > cur->pos && candidate->pos <
                (uint32_t)(cur->pos + cur->len)) {
            return true;
        }
    }
    return false;
}

static bool is_valid_for_input_len(const mutation_op_t *op,
                                  const ca_plan_limits_t *limits) {
    if (!op || !limits) return false;
    if (!op_is_supported(op)) return false;

    size_t input_len = limits->input_len;

    if (op->kind == CA_OP_INSERT_BYTES) {
        return op->arg.insert.data_len > 0 && op->arg.insert.data != NULL &&
               op->len == op->arg.insert.data_len && op->pos <= input_len;
    }

    if (op->kind == CA_OP_DELETE_RANGE) {
        if (op->len == 0) return false;
        if (input_len == 0) return false;
        if (op->pos >= input_len) return false;
        return (uint64_t)op->pos + (uint64_t)op->len <= input_len;
    }

    if (op_is_point(op)) {
        if (op->kind == CA_OP_BIT_FLIP && op->arg.bit_flip.bit_index >= 8u) {
            return false;
        }
        if ((op->kind == CA_OP_ADD_BYTE || op->kind == CA_OP_SUB_BYTE) &&
            op->arg.arithmetic.delta == 0u) {
            return false;
        }
        if (op->kind == CA_OP_SET_BYTE && limits->input != NULL &&
            input_len > 0 && limits->input[op->pos] == op->arg.set_byte.value) {
            return false;
        }
        return op->len == 1 && op->pos < input_len;
    }

    return false;
}

ca_status_t mutation_plan_normalize(const mutation_plan_t *source,
                                   const ca_plan_limits_t *limits,
                                   normalized_plan_t *result) {
    if (!source || !limits || !result) return CA_STATUS_INVALID_ARGUMENT;
    if (result->ops || result->extra_bytes) {
        normalized_plan_free(result);
    }
    *result = (normalized_plan_t){0};

    if (source->op_count == 0) {
        return CA_STATUS_OK;
    }

    mutation_op_t *candidates =
        (mutation_op_t *)malloc(source->op_count * sizeof(*candidates));
    if (!candidates) return CA_STATUS_OUT_OF_MEMORY;

    for (size_t i = 0; i < source->op_count; ++i) {
        candidates[i] = source->ops[i];
        if (candidates[i].source_index == 0) candidates[i].source_index = (uint32_t)(i + 1);
        if (candidates[i].kind == CA_OP_INSERT_BYTES && candidates[i].arg.insert.data_len == 0) {
            candidates[i].len = 0;
            continue;
        }
        if (candidates[i].kind == CA_OP_INSERT_BYTES) {
            candidates[i].arg.insert.data_len = candidates[i].len;
        }
    }

    mutation_plan_t source_view = {
        .extra_bytes = source->extra_bytes,
        .extra_bytes_len = source->extra_bytes_len,
    };

    if (source->op_count > 1) {
        qsort(candidates, source->op_count, sizeof(*candidates), cmp_score);
    }

    normalized_plan_t accepted = {0};
    for (size_t i = 0; i < source->op_count; ++i) {
        mutation_op_t candidate = candidates[i];

        if (!is_valid_for_input_len(&candidate, limits)) continue;
        if (candidate.kind == CA_OP_INSERT_BYTES &&
            (candidate.arg.insert.data == NULL || candidate.arg.insert.data_len != candidate.len)) {
            continue;
        }
        if (limits->max_ops != 0 && accepted.op_count >= limits->max_ops) break;

        if (op_conflicts(&candidate, &accepted)) continue;

        ca_status_t status = append_to_plan(&accepted, &source_view, &candidate);
        if (status != CA_STATUS_OK) {
            normalized_plan_free(&accepted);
            free(candidates);
            return status;
        }
    }

    free(candidates);

    size_t output_len = 0;
    if (mutation_plan_measure(&accepted, limits->input_len,
                             &output_len) != CA_STATUS_OK) {
        normalized_plan_free(&accepted);
        return CA_STATUS_INVALID_ARGUMENT;
    }

    while (output_len > limits->max_output_len && accepted.op_count > 0) {
        size_t remove_idx = accepted.op_count;
        uint32_t lowest_score = UINT32_MAX;
        uint32_t tie_source = UINT32_MAX;

        for (size_t i = 0; i < accepted.op_count; ++i) {
            if (accepted.ops[i].kind != CA_OP_INSERT_BYTES) continue;
            if (accepted.ops[i].score < lowest_score ||
                (accepted.ops[i].score == lowest_score &&
                 accepted.ops[i].source_index < tie_source)) {
                lowest_score = accepted.ops[i].score;
                remove_idx = i;
                tie_source = accepted.ops[i].source_index;
            }
        }

        if (remove_idx >= accepted.op_count) break;

        for (size_t i = remove_idx + 1; i < accepted.op_count; ++i) {
            accepted.ops[i - 1] = accepted.ops[i];
        }
        accepted.op_count -= 1;

        if (mutation_plan_measure(&accepted, limits->input_len,
                                 &output_len) != CA_STATUS_OK) {
            normalized_plan_free(&accepted);
            return CA_STATUS_INVALID_ARGUMENT;
        }
    }

    if (output_len > limits->max_output_len) {
        normalized_plan_free(&accepted);
        return CA_STATUS_OUTPUT_TOO_LARGE;
    }

    if (accepted.op_count > 1) {
        qsort(accepted.ops, accepted.op_count, sizeof(*accepted.ops),
              cmp_pos_then_source);
    }
    *result = accepted;
    return CA_STATUS_OK;
}

ca_status_t mutation_plan_measure(const normalized_plan_t *plan, size_t input_len,
                                 size_t *output_len) {
    if (!plan || !output_len) return CA_STATUS_INVALID_ARGUMENT;

    size_t removed = 0;
    size_t inserted = 0;

    for (size_t i = 0; i < plan->op_count; ++i) {
        const mutation_op_t *op = &plan->ops[i];
        switch (op->kind) {
            case CA_OP_BIT_FLIP:
            case CA_OP_SET_BYTE:
            case CA_OP_ADD_BYTE:
            case CA_OP_SUB_BYTE:
                if (op->len != 1 || op->pos >= input_len) {
                    return CA_STATUS_INVALID_ARGUMENT;
                }
                break;
            case CA_OP_DELETE_RANGE:
                if (op->len == 0 || op->pos >= input_len ||
                    (uint64_t)op->pos + (uint64_t)op->len > input_len) {
                    return CA_STATUS_INVALID_ARGUMENT;
                }
                if (size_add_overflow(removed, (size_t)op->len, &removed)) {
                    return CA_STATUS_OUT_OF_MEMORY;
                }
                break;
            case CA_OP_INSERT_BYTES: {
                if (op->len == 0 || op->arg.insert.data_len == 0 ||
                    op->arg.insert.data_len != op->len || op->pos > input_len ||
                    op->arg.insert.data == NULL) {
                    return CA_STATUS_INVALID_ARGUMENT;
                }
                if (size_add_overflow(inserted, (size_t)op->len, &inserted)) {
                    return CA_STATUS_OUT_OF_MEMORY;
                }
                break;
            }
            default:
                return CA_STATUS_INVALID_ARGUMENT;
        }
    }

    size_t base_len = 0;
    if (size_sub_underflow(input_len, removed, &base_len)) {
        return CA_STATUS_INVALID_ARGUMENT;
    }

    if (size_add_overflow(base_len, inserted, output_len)) {
        return CA_STATUS_OUT_OF_MEMORY;
    }

    return CA_STATUS_OK;
}

static const mutation_op_t *find_point_at(const normalized_plan_t *plan, uint32_t pos) {
    for (size_t i = 0; i < plan->op_count; ++i) {
        if (op_is_point(&plan->ops[i]) && plan->ops[i].pos == pos) {
            return &plan->ops[i];
        }
    }
    return NULL;
}

static const mutation_op_t *find_insert_at(const normalized_plan_t *plan,
                                          uint32_t pos) {
    for (size_t i = 0; i < plan->op_count; ++i) {
        if (plan->ops[i].kind == CA_OP_INSERT_BYTES && plan->ops[i].pos == pos) {
            return &plan->ops[i];
        }
    }
    return NULL;
}

static bool is_deleted_pos(const normalized_plan_t *plan, uint32_t pos) {
    for (size_t i = 0; i < plan->op_count; ++i) {
        if (plan->ops[i].kind == CA_OP_DELETE_RANGE &&
            delete_contains_pos(&plan->ops[i], pos)) {
            return true;
        }
    }
    return false;
}

ca_status_t mutation_plan_apply(const normalized_plan_t *plan, const uint8_t *input,
                               size_t input_len, uint8_t *output,
                               size_t output_capacity, size_t *output_len) {
    if (!plan || !output || !output_len) return CA_STATUS_INVALID_ARGUMENT;
    if (input_len != 0 && input == NULL) return CA_STATUS_INVALID_ARGUMENT;

    size_t expected_len = 0;
    ca_status_t st = mutation_plan_measure(plan, input_len, &expected_len);
    if (st != CA_STATUS_OK) return st;
    if (expected_len > output_capacity) return CA_STATUS_INTERNAL_ERROR;

    size_t out = 0;
    for (uint32_t pos = 0; pos <= input_len; ++pos) {
        const mutation_op_t *insert = find_insert_at(plan, pos);
        if (insert) {
            if (!insert->arg.insert.data) return CA_STATUS_INVALID_ARGUMENT;
            if (insert->arg.insert.data_len == 0 ||
                out + insert->arg.insert.data_len > output_capacity) {
                return CA_STATUS_INTERNAL_ERROR;
            }
            memcpy(output + out, insert->arg.insert.data, insert->arg.insert.data_len);
            out += insert->arg.insert.data_len;
        }

        if (pos == input_len) break;
        if (is_deleted_pos(plan, pos)) continue;

        uint8_t byte = input[pos];
        const mutation_op_t *point = find_point_at(plan, pos);
        if (point) {
            if (point->kind == CA_OP_BIT_FLIP) {
                byte ^= (uint8_t)(1u << (point->arg.bit_flip.bit_index & 7u));
            } else if (point->kind == CA_OP_SET_BYTE) {
                byte = point->arg.set_byte.value;
            } else if (point->kind == CA_OP_ADD_BYTE) {
                byte = (uint8_t)(byte + (int8_t)point->arg.arithmetic.delta);
            } else if (point->kind == CA_OP_SUB_BYTE) {
                byte = (uint8_t)(byte - (int8_t)point->arg.arithmetic.delta);
            }
        }
        output[out++] = byte;
    }

    *output_len = out;
    return CA_STATUS_OK;
}
