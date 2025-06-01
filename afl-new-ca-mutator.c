#if defined(__GNUC__) || defined(__clang__)
#  define MAYBE_UNUSED __attribute__((unused))
#else
#  define MAYBE_UNUSED
#endif

#define AFL_MAIN                        // Нужно для некоторых определений из AFL++ headers
#include "afl-fuzz.h"                   // Основной заголовочный файл AFL++

// Попытка включить config.h, который обычно определяет RAND_CACHE_SIZE
// Убедитесь, что config.h находится в пути, указанном через -I (например, /afl/include/config.h)
#if __has_include("config.h") || defined(HAVE_CONFIG_H) // Более безопасная проверка для include
#include "config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>                       // Для sqrt
#include <time.h>                       // Для возможного fallback ГПСЧ

// Заголовочный файл для OpenMP, если используется
#if defined(_OPENMP)
#include <omp.h>
#endif

// Максимальные размеры сетки для предотвращения чрезмерного использования памяти
#define MAX_GRID_DIM 256

// Если RAND_CACHE_SIZE все еще не определен после попытки включить config.h
#ifndef RAND_CACHE_SIZE
#define RAND_CACHE_SIZE 256
#warning "RAND_CACHE_SIZE was not defined by AFL++ headers (config.h potentially missing or doesn't define it), using default 256. Check your AFL++ include paths and headers."
#endif


// Структура для хранения состояния нашего мутатора
typedef struct {
    afl_state_t *afl;         // Указатель на состояние AFL++
    uint8_t *grid_cur;        // Текущее состояние сетки КА
    uint8_t *grid_next;       // Следующее состояние сетки КА
    size_t grid_capacity;     // Текущая выделенная емкость для сеток (в ячейках)
} my_mutator_t;

MAYBE_UNUSED void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data) {
        perror("Failed to allocate my_mutator_t in afl_custom_init");
        return NULL;
    }
    data->afl = afl;
    (void)seed; // Подавляем предупреждение о неиспользуемом параметре, если seed не используется
    return data;
}

MAYBE_UNUSED void afl_custom_deinit(void *data) {
    my_mutator_t *mutator_data = (my_mutator_t *)data;
    if (mutator_data) {
        free(mutator_data->grid_cur);
        free(mutator_data->grid_next);
        free(mutator_data);
    }
}

MAYBE_UNUSED size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                                     uint8_t **out_buf_ptr, MAYBE_UNUSED uint8_t *add_buf,
                                     MAYBE_UNUSED size_t add_buf_size, size_t max_size) {
    my_mutator_t *mutator_data = (my_mutator_t *)data;

    if (buf_size == 0) {
        *out_buf_ptr = NULL;
        return 0;
    }

    int width, height;
    if (buf_size == 1) {
        width = 1;
        height = 1;
    } else {
        width = (int)sqrt((double)buf_size);
        if (width <= 0) width = 1;
        if (width > MAX_GRID_DIM) width = MAX_GRID_DIM;

        height = (buf_size + width - 1) / width;
        if (height <= 0) height = 1;
        if (height > MAX_GRID_DIM) height = MAX_GRID_DIM;
    }

    size_t total_cells = (size_t)width * height;
    if (total_cells == 0) {
         *out_buf_ptr = NULL;
         return 0;
    }

    if (total_cells > mutator_data->grid_capacity) {
        free(mutator_data->grid_cur);
        free(mutator_data->grid_next);

        mutator_data->grid_cur = (uint8_t *)malloc(total_cells);
        mutator_data->grid_next = (uint8_t *)malloc(total_cells);

        if (!mutator_data->grid_cur || !mutator_data->grid_next) {
            if(mutator_data->grid_cur) free(mutator_data->grid_cur);
            if(mutator_data->grid_next) free(mutator_data->grid_next);
            mutator_data->grid_cur = NULL;
            mutator_data->grid_next = NULL;
            mutator_data->grid_capacity = 0;
            *out_buf_ptr = NULL;
            return 0;
        }
        mutator_data->grid_capacity = total_cells;
    }

    size_t init_size = (buf_size < total_cells) ? buf_size : total_cells;
    // *** ИСПРАВЛЕНА ОПЕЧАТКА ЗДЕСЬ ***
    memcpy(mutator_data->grid_cur, buf, init_size); // Было grid__cur 
    // **********************************
    if (total_cells > init_size) {
        memset(mutator_data->grid_cur + init_size, 0, total_cells - init_size);
    }

    int num_iterations_T = 1; 
    if (mutator_data->afl) { 
        if (mutator_data->afl->rand_cnt >= RAND_CACHE_SIZE) { 
             mutator_data->afl->rand_cnt = 0; 
        }
        uint32_t random_val = mutator_data->afl->rand_seed[mutator_data->afl->rand_cnt++];
        num_iterations_T = 1 + (random_val % 8);
    } else {
        // Резервный вариант... (маловероятен)
    }

    for (int iter = 0; iter < num_iterations_T; ++iter) {
        #if defined(_OPENMP)
        #pragma omp parallel for collapse(2)
        #endif
        for (int r = 0; r < height; ++r) {
            for (int c = 0; c < width; ++c) {
                uint8_t xor_sum_neighbors = 0;
                for (int dr = -1; dr <= 1; ++dr) {
                    for (int dc = -1; dc <= 1; ++dc) {
                        if (dr == 0 && dc == 0) continue;
                        int nr = (r + dr + height) % height;
                        int nc = (c + dc + width) % width;
                        xor_sum_neighbors ^= mutator_data->grid_cur[nr * width + nc];
                    }
                }
                mutator_data->grid_next[r * width + c] = xor_sum_neighbors;
            }
        }
        uint8_t *tmp_grid = mutator_data->grid_cur;
        mutator_data->grid_cur = mutator_data->grid_next;
        mutator_data->grid_next = tmp_grid;
    }

    size_t out_size = total_cells;
    if (max_size > 0 && out_size > max_size) {
        out_size = max_size;
    }

    uint8_t *new_out_buf = (uint8_t *)realloc(*out_buf_ptr, out_size);
    if (!new_out_buf) {
        if (out_size > 0) { // Ошибка только если мы действительно хотели выделить память
             return 0;
        }
        // Если out_size == 0, realloc мог вернуть NULL, и это нормально (или другой валидный указатель).
        // *out_buf_ptr будет установлен в new_out_buf (т.е. NULL или другой указатель).
    }
    *out_buf_ptr = new_out_buf;

    if (out_size > 0 && *out_buf_ptr) { // Убедимся, что есть что копировать и куда копировать
        memcpy(*out_buf_ptr, mutator_data->grid_cur, out_size);
    } else if (out_size == 0) {
        // out_size == 0, memcpy не нужен, *out_buf_ptr уже установлен
    } else { // out_size > 0 но *out_buf_ptr == NULL (ошибка realloc, которая должна была быть обработана выше)
        return 0; 
    }

    return out_size;
}