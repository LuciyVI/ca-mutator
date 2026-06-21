#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef CA_GROWING_DEBUG
#include <stdio.h>
#endif

#include "ca_engine_internal.h"
#include "growing_engine.h"
#include "mutation_plan.h"

#define CA_GROW_BLOCK_SIZE 16u

typedef struct {
    uint16_t byte_sum;
    uint8_t printable;
    uint8_t filled;
    uint8_t entropy;
    uint8_t activity;
    uint16_t channels[6];
    size_t position;
} growing_cell_t;

typedef struct {
    uint8_t *input;
    size_t input_len;
    size_t block_size;
    size_t cell_count;
    ca_rng_t rng;
    mutation_plan_t plan;
    growing_cell_t *cells;

#ifdef CA_GROWING_DEBUG
    size_t debug_raw_ops;
    size_t debug_candidate_ops;
    size_t debug_rejected_ops;
    size_t debug_accepted_ops;
    size_t debug_steps;
    size_t debug_cell_count;
    uint64_t debug_input_hash;
    uint64_t debug_output_hash;
    uint64_t debug_mutation_id;
    size_t debug_removed_inserts;
    size_t debug_conflicts;
    size_t debug_rng_calls;
#endif
} ca_growing_engine_t;

static void ca_growing_reset_state(ca_growing_engine_t *engine) {
    if (!engine) return;
    mutation_plan_destroy(&engine->plan);
#ifdef CA_GROWING_DEBUG
    engine->debug_raw_ops = 0;
    engine->debug_candidate_ops = 0;
    engine->debug_rejected_ops = 0;
    engine->debug_accepted_ops = 0;
    engine->debug_steps = 0;
    engine->debug_cell_count = 0;
    engine->debug_input_hash = 0;
    engine->debug_output_hash = 0;
    engine->debug_mutation_id = 0;
    engine->debug_removed_inserts = 0;
    engine->debug_conflicts = 0;
    engine->debug_rng_calls = 0;
#endif
}

#ifdef CA_GROWING_DEBUG
static uint64_t grow_hash64(const uint8_t *data, size_t len) {
    uint64_t hash = 1469598103934665603ULL;
    const uint64_t prime = 1099511628211ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= (uint64_t)data[i];
        hash *= prime;
    }
    return hash;
}
#endif

static bool is_noop_candidate(const ca_growing_engine_t *engine,
                             const mutation_op_t *candidate) {
    if (!engine || !candidate) return true;

    if (candidate->kind == CA_OP_BIT_FLIP) {
        if (candidate->arg.bit_flip.bit_index > 7u) return true;
        return candidate->len != 1;
    }

    if (candidate->kind == CA_OP_SET_BYTE) {
        if (candidate->len != 1 || candidate->pos >= engine->input_len) return true;
        if (engine->input_len == 0) return true;
        return engine->input[candidate->pos] == candidate->arg.set_byte.value;
    }

    if (candidate->kind == CA_OP_ADD_BYTE || candidate->kind == CA_OP_SUB_BYTE) {
        return candidate->len != 1 || candidate->arg.arithmetic.delta == 0u;
    }

    if (candidate->kind == CA_OP_DELETE_RANGE) {
        if (candidate->len == 0 || engine->input_len == 0) return true;
        if (candidate->pos >= engine->input_len) return true;
        return (uint64_t)candidate->pos + (uint64_t)candidate->len > engine->input_len;
    }

    if (candidate->kind == CA_OP_INSERT_BYTES) {
        if (candidate->len == 0) return true;
        if (candidate->pos > engine->input_len) return true;
        if (candidate->arg.insert.data_len != 0 &&
            candidate->arg.insert.data_len != candidate->len) {
            return true;
        }
        return false;
    }

    return true;
}

static uint32_t grow_below(ca_growing_engine_t *engine, uint32_t limit) {
    if (!engine->rng.below || limit == 0) return 0u;
#ifdef CA_GROWING_DEBUG
    ++engine->debug_rng_calls;
#endif
    return engine->rng.below(engine->rng.context, limit);
}

static uint8_t grow_u8(ca_growing_engine_t *engine) {
    return (uint8_t)grow_below(engine, 256u);
}

static size_t grow_u32_range(ca_growing_engine_t *engine, size_t max_inclusive) {
    if (!engine || max_inclusive == 0u) return 0u;
    if (max_inclusive > UINT32_MAX) {
        return (size_t)grow_below(engine, UINT32_MAX);
    }
    return (size_t)grow_below(engine, (uint32_t)(max_inclusive + 1u));
}

static size_t grow_span_pos(ca_growing_engine_t *engine, const growing_cell_t *cell) {
    if (!cell || cell->filled == 0) return 0u;
    return (size_t)grow_below(engine, (uint32_t)cell->filled);
}

static uint8_t is_printable(uint8_t b) {
    return (b >= 0x20 && b <= 0x7E) ? 1u : 0u;
}

static void grow_encode_cell(ca_growing_engine_t *engine, growing_cell_t *cell,
                            size_t index) {
    size_t start = index * engine->block_size;
    size_t end =
        (start + engine->block_size > engine->input_len)
            ? engine->input_len
            : (start + engine->block_size);

    cell->position = start;
    cell->filled = (uint8_t)(end - start);
    cell->byte_sum = 0;
    cell->printable = 0;
    cell->entropy = 0;
    cell->activity = 0;

    memset(cell->channels, 0, sizeof(cell->channels));

    if (cell->filled == 0) {
        return;
    }

    for (size_t i = start; i < end; ++i) {
        uint8_t b = engine->input[i];
        cell->byte_sum ^= (uint16_t)b;
        cell->printable += is_printable(b);
        cell->entropy = (uint8_t)(cell->entropy + (uint8_t)(b ^ (uint8_t)i));
    }

    cell->activity = (uint8_t)((cell->byte_sum + (uint16_t)(cell->printable * 31u) +
                                (uint16_t)cell->entropy) &
                               0xFFu);
    for (uint32_t ch = 0; ch < 6; ++ch) {
        cell->channels[ch] =
            (uint16_t)(((uint16_t)cell->byte_sum << (ch & 3u)) ^
                       ((uint16_t)(cell->entropy) << ch) ^
                       (uint16_t)(index * 37u + ch * 11u));
    }
}

static size_t grow_left(const ca_growing_engine_t *engine, size_t idx, size_t dist) {
    if (engine->cell_count == 0) return 0;
    if (dist == 0) return idx;
    size_t step = dist % engine->cell_count;
    return (idx >= step) ? (idx - step) : (engine->cell_count - (step - idx));
}

static size_t grow_right(const ca_growing_engine_t *engine, size_t idx, size_t dist) {
    if (engine->cell_count == 0) return 0;
    if (dist == 0) return idx;
    return (idx + (dist % engine->cell_count)) % engine->cell_count;
}

static void grow_update_cell(const ca_growing_engine_t *engine, const growing_cell_t *src,
                            growing_cell_t *dst, size_t idx) {
    const int w1 = 7;
    const int w2 = 3;
    const int w4 = 2;
    const int w8 = 1;

    uint32_t n1_l = src[grow_left(engine, idx, 1)].channels[0];
    uint32_t n1_r = src[grow_right(engine, idx, 1)].channels[0];
    uint32_t n2_l = src[grow_left(engine, idx, 2)].channels[1];
    uint32_t n2_r = src[grow_right(engine, idx, 2)].channels[1];
    uint32_t n4_l = src[grow_left(engine, idx, 4)].channels[2];
    uint32_t n4_r = src[grow_right(engine, idx, 4)].channels[2];
    uint32_t n8_l = src[grow_left(engine, idx, 8)].channels[3];
    uint32_t n8_r = src[grow_right(engine, idx, 8)].channels[3];

    int32_t weighted = (w1 * (int32_t)(n1_l + n1_r)) +
                       (w2 * (int32_t)(n2_l + n2_r)) +
                       (w4 * (int32_t)(n4_l + n4_r)) +
                       (w8 * (int32_t)(n8_l + n8_r));

    dst->position = src[idx].position;
    dst->filled = src[idx].filled;
    dst->byte_sum = (uint16_t)(src[idx].byte_sum ^ (uint16_t)weighted);
    dst->printable = (uint8_t)src[idx].printable;
    dst->entropy = (uint8_t)((src[idx].entropy + (uint8_t)(weighted >> 8)) & 0xFFu);

    int32_t act = (int32_t)src[idx].activity + (weighted >> 5);
    if (act < 0) act = 0;
    if (act > 255) act = 255;
    dst->activity = (uint8_t)act;

    for (size_t ch = 0; ch < 6; ++ch) {
        uint32_t v = src[idx].channels[ch] + (uint32_t)(weighted >> (ch + 1u));
        dst->channels[ch] = (uint16_t)(v & 0xFFFFu);
    }
}

static void grow_step_cells(ca_growing_engine_t *engine, uint32_t iterations) {
    if (!engine || !engine->cells || engine->cell_count == 0 || iterations == 0) return;

    growing_cell_t *next =
        (growing_cell_t *)calloc(engine->cell_count, sizeof(*next));
    if (!next) return;

    bool *update_mask = (bool *)calloc(engine->cell_count, sizeof(*update_mask));
    if (!update_mask) {
        free(next);
        return;
    }

    for (uint32_t step = 0; step < iterations; ++step) {
        for (size_t i = 0; i < engine->cell_count; ++i) {
            update_mask[i] = (grow_below(engine, 100u) < 60u);
        }
        memcpy(next, engine->cells, engine->cell_count * sizeof(*next));

        for (size_t i = 0; i < engine->cell_count; ++i) {
            if (update_mask[i]) {
                grow_update_cell(engine, engine->cells, next, i);
            }
        }

        growing_cell_t *tmp = engine->cells;
        engine->cells = next;
        next = tmp;
    }

    free(next);
    free(update_mask);
}

static int by_activity_desc_score(const void *left, const void *right) {
    const mutation_op_t *a = (const mutation_op_t *)left;
    const mutation_op_t *b = (const mutation_op_t *)right;
    if (a->score != b->score) {
        return (a->score < b->score) ? 1 : -1;
    }
    if (a->source_index == b->source_index) {
        return 0;
    }
    return (a->source_index < b->source_index) ? -1 : 1;
}

#ifdef CA_GROWING_DEBUG
static const char *grow_op_name(mutation_op_kind_t kind) {
    switch (kind) {
        case CA_OP_BIT_FLIP:
            return "BIT_FLIP";
        case CA_OP_SET_BYTE:
            return "SET_BYTE";
        case CA_OP_ADD_BYTE:
            return "ADD_BYTE";
        case CA_OP_SUB_BYTE:
            return "SUB_BYTE";
        case CA_OP_DELETE_RANGE:
            return "DELETE_RANGE";
        case CA_OP_INSERT_BYTES:
            return "INSERT_BYTES";
        default:
            return "UNKNOWN";
    }
}
#endif

static ca_status_t growth_decode_ops(ca_growing_engine_t *engine,
                                    size_t max_ops, size_t max_output_len,
                                    mutation_plan_t *plan_out) {
    if (!engine || !plan_out) return CA_STATUS_INVALID_ARGUMENT;

    if (mutation_plan_init(plan_out) != CA_STATUS_OK) {
        return CA_STATUS_OUT_OF_MEMORY;
    }

    if (max_ops == 0) return CA_STATUS_OK;
    if (engine->input_len == 0) {
        if (max_output_len == 0) return CA_STATUS_SKIP;
        uint8_t value = (uint8_t)grow_below((ca_growing_engine_t *)engine, 256u);
        ca_status_t status =
            mutation_plan_add_insert_bytes(plan_out, 0, &value, 1, 255, 0);
        if (status != CA_STATUS_OK) {
            mutation_plan_destroy(plan_out);
        }
        return status;
    }

    mutation_op_t *candidates =
        (mutation_op_t *)malloc(engine->cell_count * sizeof(*candidates));
    if (!candidates) return CA_STATUS_OUT_OF_MEMORY;

    size_t candidate_count = 0;
    for (size_t i = 0; i < engine->cell_count; ++i) {
        const growing_cell_t *cell = &engine->cells[i];
        uint32_t pos = (uint32_t)cell->position;
        if (cell->filled > 0) {
            pos += (uint32_t)grow_span_pos((ca_growing_engine_t *)engine, cell);
            if (pos >= engine->input_len) {
                pos = (uint32_t)(engine->input_len - 1u);
            }
        }
    mutation_op_t candidate = (mutation_op_t){
        .pos = pos,
        .source_index = (uint32_t)i,
        .score = (uint32_t)cell->activity,
        .len = 1,
        .arg = {
            .insert = {
                .data = NULL,
                .data_len = 0,
            },
        },
        .data_offset = 0,
    };

        uint8_t kind_roll = grow_u8((ca_growing_engine_t *)engine) % 6u;
        if (cell->filled == 0) {
            kind_roll = 5u;
        }

        switch (kind_roll) {
            case 0: {
                candidate.kind = CA_OP_BIT_FLIP;
                candidate.arg.bit_flip.bit_index =
                    grow_u8((ca_growing_engine_t *)engine) & 7u;
                candidate.score ^= (uint32_t)grow_u8((ca_growing_engine_t *)engine);
                break;
            }
            case 1:
                candidate.kind = CA_OP_SET_BYTE;
                candidate.arg.set_byte.value = grow_u8((ca_growing_engine_t *)engine);
                candidate.score ^= (uint32_t)(cell->channels[0] ^ cell->channels[1]);
                break;
            case 2:
                candidate.kind = CA_OP_ADD_BYTE;
                candidate.arg.arithmetic.delta = grow_u8((ca_growing_engine_t *)engine);
                candidate.score ^= (uint32_t)grow_u8((ca_growing_engine_t *)engine);
                break;
            case 3:
                candidate.kind = CA_OP_SUB_BYTE;
                candidate.arg.arithmetic.delta = grow_u8((ca_growing_engine_t *)engine);
                candidate.score ^= (uint32_t)grow_u8((ca_growing_engine_t *)engine);
                break;
            case 4: {
                candidate.kind = CA_OP_DELETE_RANGE;
                if (cell->filled == 0u) {
                    candidate.kind = CA_OP_BIT_FLIP;
                    candidate.arg.bit_flip.bit_index =
                        grow_u8((ca_growing_engine_t *)engine) & 7u;
                    break;
                }
                size_t max_len = (size_t)cell->filled;
                if (max_len > 8u) max_len = 8u;
                candidate.len = (uint32_t)(grow_u32_range((ca_growing_engine_t *)engine, max_len - 1u) + 1u);
                candidate.score ^= (uint32_t)candidate.len;
                break;
            }
            case 5:
            default:
                candidate.kind = CA_OP_INSERT_BYTES;
                candidate.len = (uint32_t)(grow_u32_range((ca_growing_engine_t *)engine, 2u) + 1u);
                candidate.arg.insert.data_len = candidate.len;
                candidate.score ^= (uint32_t)grow_u32_range((ca_growing_engine_t *)engine, 4u);
                break;
        }

#ifdef CA_GROWING_DEBUG
        ++engine->debug_raw_ops;
#endif
        if (is_noop_candidate(engine, &candidate)) {
#ifdef CA_GROWING_DEBUG
            ++engine->debug_rejected_ops;
#endif
            continue;
        }
#ifdef CA_GROWING_DEBUG
        ++engine->debug_candidate_ops;
#endif
        candidates[candidate_count] = candidate;
        ++candidate_count;
    }

    if (candidate_count == 0) {
        free(candidates);
        return CA_STATUS_OK;
    }

    qsort(candidates, candidate_count, sizeof(*candidates),
          by_activity_desc_score);

    for (size_t i = 0; i < candidate_count && i < max_ops; ++i) {
        if (candidates[i].kind == CA_OP_INSERT_BYTES) {
            uint32_t len = candidates[i].len;
            if (len == 0u) len = 1u;
            uint8_t *bytes = (uint8_t *)malloc(len);
            if (!bytes) {
                mutation_plan_destroy(plan_out);
                free(candidates);
                return CA_STATUS_OUT_OF_MEMORY;
            }
            for (uint32_t b = 0; b < len; ++b) {
                bytes[b] = grow_u8((ca_growing_engine_t *)engine);
            }
            ca_status_t st =
                mutation_plan_add_insert_bytes(plan_out, candidates[i].pos, bytes, len,
                                              candidates[i].score, candidates[i].source_index);
            free(bytes);
            if (st != CA_STATUS_OK) {
                free(candidates);
                mutation_plan_destroy(plan_out);
                return st;
            }
            continue;
        }

        if (candidates[i].kind == CA_OP_DELETE_RANGE) {
            if (candidates[i].len == 0) continue;
            ca_status_t st = mutation_plan_add_delete_range(
                plan_out, candidates[i].pos, candidates[i].len, candidates[i].score,
                candidates[i].source_index);
            if (st != CA_STATUS_OK) {
                free(candidates);
                mutation_plan_destroy(plan_out);
                return st;
            }
            continue;
        }

        if (candidates[i].kind == CA_OP_BIT_FLIP) {
            ca_status_t st = mutation_plan_add_bit_flip(plan_out, candidates[i].pos,
                                                        candidates[i].arg.bit_flip.bit_index,
                                                        candidates[i].score,
                                                        candidates[i].source_index);
            if (st != CA_STATUS_OK) {
                free(candidates);
                mutation_plan_destroy(plan_out);
                return st;
            }
            continue;
        }

        if (candidates[i].kind == CA_OP_SET_BYTE) {
            ca_status_t st = mutation_plan_add_set_byte(plan_out, candidates[i].pos,
                                                       candidates[i].arg.set_byte.value,
                                                       candidates[i].score,
                                                       candidates[i].source_index);
            if (st != CA_STATUS_OK) {
                free(candidates);
                mutation_plan_destroy(plan_out);
                return st;
            }
            continue;
        }

        if (candidates[i].kind == CA_OP_ADD_BYTE) {
            ca_status_t st =
                mutation_plan_add_add_byte(plan_out, candidates[i].pos,
                                          (int8_t)candidates[i].arg.arithmetic.delta,
                                          candidates[i].score, candidates[i].source_index);
            if (st != CA_STATUS_OK) {
                free(candidates);
                mutation_plan_destroy(plan_out);
                return st;
            }
            continue;
        }

        if (candidates[i].kind == CA_OP_SUB_BYTE) {
                ca_status_t st =
                mutation_plan_add_sub_byte(plan_out, candidates[i].pos,
                                          (int8_t)candidates[i].arg.arithmetic.delta,
                                          candidates[i].score, candidates[i].source_index);
            if (st != CA_STATUS_OK) {
                free(candidates);
                mutation_plan_destroy(plan_out);
                return st;
            }
        }
    }

    free(candidates);
    return CA_STATUS_OK;
}

static ca_status_t ca_growing_destroy(void *impl) {
    ca_growing_engine_t *engine = (ca_growing_engine_t *)impl;
    if (!engine) return CA_STATUS_OK;

    free(engine->input);
    mutation_plan_destroy(&engine->plan);
    free(engine->cells);
    free(engine);
    return CA_STATUS_OK;
}

static ca_status_t ca_growing_mutate(void *impl, const ca_mutate_request_t *request,
                                    ca_output_t *output) {
    ca_growing_engine_t *engine = (ca_growing_engine_t *)impl;
    if (!engine || !request || !output) return CA_STATUS_INVALID_ARGUMENT;
    if (!request->input && request->input_len != 0) return CA_STATUS_INVALID_ARGUMENT;

    ca_growing_reset_state(engine);
    if (request->max_output_len == 0) {
        return CA_STATUS_SKIP;
    }

    engine->input_len = request->input_len;
    if (request->input_len > 0) {
        uint8_t *next_input = (uint8_t *)realloc(engine->input, request->input_len);
        if (!next_input) return CA_STATUS_OUT_OF_MEMORY;
        engine->input = next_input;
        memcpy(engine->input, request->input, request->input_len);
    } else {
        free(engine->input);
        engine->input = NULL;
    }

    engine->block_size = CA_GROW_BLOCK_SIZE;
    engine->cell_count =
        (request->input_len + engine->block_size - 1u) / engine->block_size;

    if (engine->cell_count == 0) {
        engine->cell_count = 1;
    }

    free(engine->cells);
    engine->cells =
        (growing_cell_t *)calloc(engine->cell_count, sizeof(*engine->cells));
    if (!engine->cells) return CA_STATUS_OUT_OF_MEMORY;

    for (size_t i = 0; i < engine->cell_count; ++i) {
        grow_encode_cell(engine, &engine->cells[i], i);
    }

    uint32_t steps = 1u + grow_below(engine, 5u);
    grow_step_cells(engine, steps);

    size_t max_ops = 1u + (engine->cell_count / 64u);
    if (max_ops > 8u) max_ops = 8u;

#ifdef CA_GROWING_DEBUG
    engine->debug_raw_ops = 0;
    engine->debug_candidate_ops = 0;
    engine->debug_rejected_ops = 0;
    engine->debug_steps = (size_t)steps;
    engine->debug_cell_count = engine->cell_count;
    engine->debug_mutation_id = request->mutation_id;
    engine->debug_removed_inserts = 0;
    engine->debug_conflicts = 0;
    engine->debug_output_hash = 0;
    engine->debug_input_hash = grow_hash64(request->input, request->input_len);
#endif

    mutation_plan_t source_plan = {0};
    ca_status_t decode_status =
        growth_decode_ops(engine, max_ops, request->max_output_len, &source_plan);
    if (decode_status != CA_STATUS_OK) {
        return decode_status;
    }

    ca_plan_limits_t limits = {
        .max_ops = max_ops,
        .max_output_len = request->max_output_len,
        .input_len = request->input_len,
        .input = request->input,
    };

    normalized_plan_t normalized = {0};
    ca_status_t norm_status =
        mutation_plan_normalize(&source_plan, &limits, &normalized);
    mutation_plan_destroy(&source_plan);
    if (norm_status != CA_STATUS_OK) {
        normalized_plan_free(&normalized);
        return norm_status;
    }
    if (normalized.op_count == 0) {
        normalized_plan_free(&normalized);
        return CA_STATUS_SKIP;
    }

#ifdef CA_GROWING_DEBUG
    engine->debug_accepted_ops = normalized.op_count;
    for (size_t i = 0; i < normalized.op_count; ++i) {
        mutation_op_t *op = &normalized.ops[i];
        fprintf(stderr,
                "[growing] op#%zu kind=%s pos=%u len=%u score=%u src=%u",
                i, grow_op_name(op->kind), op->pos, op->len, op->score,
                op->source_index);
        if (op->kind == CA_OP_INSERT_BYTES) {
            fprintf(stderr, " ins_len=%zu", (size_t)op->arg.insert.data_len);
        }
        fprintf(stderr, "\n");
    }
#endif

    engine->plan.ops = normalized.ops;
    engine->plan.op_count = normalized.op_count;
    engine->plan.extra_bytes = normalized.extra_bytes;
    engine->plan.extra_bytes_len = normalized.extra_bytes_len;

#ifdef CA_GROWING_DEBUG
    engine->debug_input_hash = grow_hash64(request->input, request->input_len);
    fprintf(stderr,
            "[growing] mutation=%" PRIu64
            " input_len=%zu steps=%zu cells=%zu raw=%zu candidate=%zu rejected=%zu accepted=%zu input_hash=%016" PRIx64
            " rng_calls=%zu\n",
            (uint64_t)request->mutation_id, request->input_len, engine->debug_steps,
            engine->debug_cell_count, engine->debug_raw_ops, engine->debug_candidate_ops,
            engine->debug_rejected_ops, engine->debug_accepted_ops, engine->debug_input_hash,
            engine->debug_rng_calls);
#endif

    output->kind = CA_OUTPUT_PLAN;
    output->value.plan = &engine->plan;
    return CA_STATUS_OK;
}

ca_status_t ca_engine_create_growing_impl(const ca_engine_config_t *config, ca_rng_t rng,
                                         ca_engine_t **engine) {
    if (!engine || !rng.below) return CA_STATUS_INVALID_ARGUMENT;
    (void)config;

    ca_growing_engine_t *impl = (ca_growing_engine_t *)calloc(1, sizeof(*impl));
    if (!impl) return CA_STATUS_OUT_OF_MEMORY;
    impl->rng = rng;
    impl->block_size = CA_GROW_BLOCK_SIZE;

    ca_engine_t *base = (ca_engine_t *)calloc(1, sizeof(*base));
    if (!base) {
        free(impl);
        return CA_STATUS_OUT_OF_MEMORY;
    }

    base->impl = impl;
    base->rng = rng;
    base->output_kind = CA_OUTPUT_PLAN;
    base->destroy = ca_growing_destroy;
    base->mutate = ca_growing_mutate;
    *engine = base;
    return CA_STATUS_OK;
}
