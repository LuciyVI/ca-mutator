// Сохраните этот код как my_mutator.c
#define AFL_MAIN
#include "afl-fuzz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#define MAX_GRID_DIM 512
#define PRIORITY_BUMP 32
#define PRIORITY_DECAY 1

#if defined(__GNUC__) || defined(__clang__)
#  define MAYBE_UNUSED __attribute__((unused))
#else
#  define MAYBE_UNUSED
#endif

typedef struct my_mutator_t {
    afl_state_t *afl;
    uint8_t *grid_cur;
    uint8_t *grid_next;
    uint8_t *priority_map;
    size_t capacity;
} my_mutator_t;

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data) { perror("calloc failed"); return NULL; }
    data->afl = afl;
    srand(seed);
    return data;
}

void afl_custom_deinit(void *data) {
    my_mutator_t *d = (my_mutator_t *)data;
    if (d) { free(d->grid_cur); free(d->grid_next); free(d->priority_map); free(d); }
}

void afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size, uint8_t* match_bits) {
    #ifdef STANDALONE_TEST
    // В тестовом режиме эта функция ничего не делает
    (void)data; (void)buf; (void)buf_size; (void)match_bits;
    return;
    #else
    my_mutator_t *mutator = (my_mutator_t *)data;
    afl_state_t *afl = mutator->afl;
    int found_new_coverage = 0;
    if (afl && afl->virgin_bits && match_bits) {
        for (u32 i = 0; i < afl->fsrv.map_size; i++) {
            if (match_bits[i] & afl->virgin_bits[i]) { found_new_coverage = 1; break; }
        }
    }
    if (found_new_coverage) {
        if (buf_size > 0 && mutator->priority_map && buf_size <= mutator->capacity) {
            for (size_t i = 0; i < buf_size; ++i) {
                if (buf[i]) {
                    if (mutator->priority_map[i] < 255 - PRIORITY_BUMP) mutator->priority_map[i] += PRIORITY_BUMP;
                    else mutator->priority_map[i] = 255;
                }
            }
        }
    }
    #endif
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf_ptr, MAYBE_UNUSED uint8_t *add_buf, MAYBE_UNUSED size_t add_buf_size, size_t max_size) {
    my_mutator_t *mutator = (my_mutator_t *)data;
    if (buf_size == 0) { *out_buf_ptr = buf; return buf_size; }
    int width, height;
    if (buf_size == 1) { width = 1; height = 1; }
    else {
        width = (int)sqrt((double)buf_size);
        if (width <= 0) width = 1; if (width > MAX_GRID_DIM) width = MAX_GRID_DIM;
        height = (buf_size + width - 1) / width;
        if (height <= 0) height = 1; if (height > MAX_GRID_DIM) height = MAX_GRID_DIM;
    }
    size_t total_cells = (size_t)width * height;
    if (total_cells == 0) { *out_buf_ptr = buf; return buf_size; }
    if (total_cells > mutator->capacity) {
        free(mutator->grid_cur); free(mutator->grid_next); free(mutator->priority_map);
        mutator->grid_cur = malloc(total_cells); mutator->grid_next = malloc(total_cells); mutator->priority_map = calloc(total_cells, 1);
        if (!mutator->grid_cur || !mutator->grid_next || !mutator->priority_map) {
            free(mutator->grid_cur); free(mutator->grid_next); free(mutator->priority_map);
            mutator->grid_cur = mutator->grid_next = mutator->priority_map = NULL;
            mutator->capacity = 0; *out_buf_ptr = buf; return buf_size;
        }
        mutator->capacity = total_cells;
    }
    size_t init_size = (buf_size < total_cells) ? buf_size : total_cells;
    memcpy(mutator->grid_cur, buf, init_size);
    if (total_cells > init_size) memset(mutator->grid_cur + init_size, 0, total_cells - init_size);
    
    #ifndef STANDALONE_TEST
    for (size_t i = 0; i < total_cells; ++i) {
        if (mutator->priority_map[i] > PRIORITY_DECAY) mutator->priority_map[i] -= PRIORITY_DECAY;
        else mutator->priority_map[i] = 0;
    }
    #endif

    int num_iterations;
    #ifdef STANDALONE_TEST
    num_iterations = 1 + (rand() % 8);
    #else
    num_iterations = 1 + (rand_below(mutator->afl, 8));
    #endif
    
    for (int iter = 0; iter < num_iterations; ++iter) {
        for (int r = 0; r < height; ++r) {
            for (int c = 0; c < width; ++c) {
                size_t idx = (size_t)r * width + c;
                #ifdef STANDALONE_TEST
                (void)mutator; // Подавляем предупреждение о неиспользуемой переменной
                mutator->grid_next[idx] = mutator->grid_cur[idx] ^ (rand() % 256);
                #else
                uint8_t priority = mutator->priority_map[idx];
                if (rand_below(mutator->afl, 256) < priority) {
                    mutator->grid_next[idx] = mutator->grid_cur[idx] ^ (1 << rand_below(mutator->afl, 8));
                } else {
                    uint8_t xor_sum = 0;
                    for (int dr = -1; dr <= 1; ++dr) for (int dc = -1; dc <= 1; ++dc) {
                        if (dr == 0 && dc == 0) continue;
                        xor_sum ^= mutator->grid_cur[((r + dr + height) % height) * width + ((c + dc + width) % width)];
                    }
                    mutator->grid_next[idx] = xor_sum;
                }
                #endif
            }
        }
        uint8_t *tmp = mutator->grid_cur; mutator->grid_cur = mutator->grid_next; mutator->grid_next = tmp;
    }
    size_t out_size = total_cells; if (max_size > 0 && out_size > max_size) out_size = max_size;
    uint8_t* mutated_out = malloc(out_size);
    if (!mutated_out) { *out_buf_ptr = buf; return buf_size; }
    memcpy(mutated_out, mutator->grid_cur, out_size);
    *out_buf_ptr = mutated_out;
    return out_size;
}