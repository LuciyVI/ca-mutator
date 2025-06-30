#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "afl-fuzz.h" // Подключаем для доступа к afl_state_t и MAX_FILE

#if defined(__GNUC__) || defined(__clang__)
#  define MAYBE_UNUSED __attribute__((unused))
#else
#  define MAYBE_UNUSED
#endif

// Структура мутатора.
typedef struct my_mutator {
    afl_state_t *afl;
    uint8_t *grid_cur;  // Рабочий буфер для текущего состояния
    uint8_t *grid_next; // Рабочий буфер для следующего состояния
    size_t capacity;    // Размер буферов (будет равен MAX_FILE)
} my_mutator_t;

/**
 * Инициализация мутатора. Вызывается один раз при старте afl-fuzz.
 */
void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    // Используем seed для генератора случайных чисел AFL++
    (void)seed; 

    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data) {
        perror("afl_custom_init alloc");
        return NULL;
    }

    data->afl = afl;
    
    // Устанавливаем нашу емкость равной стандартному максимальному размеру файла AFL++
    data->capacity = MAX_FILE;

    // Выделяем память для ДВУХ наших буферов ОДИН РАЗ, по аналогии с Radamsa.
    data->grid_cur = malloc(data->capacity);
    data->grid_next = malloc(data->capacity);

    if (!data->grid_cur || !data->grid_next) {
        free(data->grid_cur);
        free(data->grid_next);
        free(data);
        perror("afl_custom_init buffers alloc");
        return NULL;
    }

    return data;
}

/**
 * Деинициализация мутатора. Вызывается при завершении работы afl-fuzz.
 */
void afl_custom_deinit(void *data) {
    my_mutator_t *d = (my_mutator_t *)data;
    if (d) {
        // Освобождаем память, выделенную в init.
        free(d->grid_cur);
        free(d->grid_next);
        free(d);
    }
}

/**
 * Основная функция мутации.
 */
size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf MAYBE_UNUSED,
    size_t add_buf_size MAYBE_UNUSED,
    size_t max_size) {

    my_mutator_t *mutator = (my_mutator_t *)data;
    
    // Определяем рабочий размер, но не больше, чем емкость наших буферов.
    size_t working_size = buf_size;
    if (working_size > mutator->capacity) {
        working_size = mutator->capacity;
    }
    
    // Обработка пустого входа
    if (working_size == 0) {
        mutator->grid_cur[0] = rand_below(mutator->afl, 256);
        *out_buf = mutator->grid_cur;
        return 1;
    }

    // --- Логика клеточного автомата (остается без изменений) ---
    int width = 256;
    if ((size_t)width > working_size) { width = working_size; }
    if (width <= 0) width = 1;

    int height = (working_size + width - 1) / width;
    if (height <= 0) height = 1;

    size_t total_cells = (size_t)width * (size_t)height;

    memcpy(mutator->grid_cur, buf, working_size);
    if (total_cells > working_size && total_cells <= mutator->capacity) {
        memset(mutator->grid_cur + working_size, 0, total_cells - working_size);
    }
    
    int num_iterations = 1 + rand_below(mutator->afl, 8);

    for (int iter = 0; iter < num_iterations; ++iter) {
        for (int r = 0; r < height; ++r) {
            for (int c = 0; c < width; ++c) {
                size_t idx = (size_t)r * (size_t)width + (size_t)c;
                if (rand_below(mutator->afl, 4) == 0) {
                    mutator->grid_next[idx] = mutator->grid_cur[idx] ^ (1 << rand_below(mutator->afl, 8));
                } else {
                    uint8_t xor_sum = 0;
                    for (int dr = -1; dr <= 1; ++dr) {
                        for (int dc = -1; dc <= 1; ++dc) {
                            if (dr == 0 && dc == 0) continue;
                            int nr = (r + dr + height) % height;
                            int nc = (c + dc + width) % width;
                            xor_sum ^= mutator->grid_cur[(size_t)nr * (size_t)width + (size_t)nc];
                        }
                    }
                    mutator->grid_next[idx] = xor_sum;
                }
            }
        }
        uint8_t *tmp = mutator->grid_cur;
        mutator->grid_cur = mutator->grid_next;
        mutator->grid_next = tmp;
    }
    // --- Конец логики клеточного автомата ---

    size_t out_size = total_cells;
    // Уважаем лимит максимального размера, заданный AFL++
    if (out_size > max_size) {
        out_size = max_size;
    }

    // Говорим AFL++, что результат находится в нашем заранее выделенном буфере.
    *out_buf = mutator->grid_cur;

    return out_size;
}