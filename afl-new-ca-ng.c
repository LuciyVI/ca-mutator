#define AFL_MAIN
#include "afl-fuzz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

// Максимальный размер выходного буфера
#define MAX_MUTATION_SIZE 1024
// Максимальный размер одного измерения сетки
#define MAX_GRID_DIM      512

#if defined(__GNUC__) || defined(__clang__)
#  define MAYBE_UNUSED __attribute__((unused))
#else
#  define MAYBE_UNUSED
#endif

typedef struct my_mutator {
    afl_state_t *afl;
    uint8_t *grid_cur;
    uint8_t *grid_next;
    size_t capacity;
} my_mutator_t;

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    (void)seed;

    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data) return NULL;

    data->afl = afl;
    return data;
}

void afl_custom_deinit(void *data) {
    my_mutator_t *d = (my_mutator_t *)data;
    if (d) {
        free(d->grid_cur);
        free(d->grid_next);
        free(d);
    }
}

// Эта функция больше не используется в современных версиях AFL++ для кастомных мутаторов,
// но оставим ее для совместимости.
void afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size, uint8_t *match_bits) {
    (void)data; (void)buf; (void)buf_size; (void)match_bits;
}

size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf MAYBE_UNUSED,
    size_t add_buf_size MAYBE_UNUSED,
    size_t max_size) {

    my_mutator_t *mutator = (my_mutator_t *)data;

    // Ограничиваем максимальный размер выходных данных
    if (max_size == 0 || max_size > MAX_MUTATION_SIZE) {
        max_size = MAX_MUTATION_SIZE;
    }

    // ДОБАВЛЕНО: Определяем рабочий размер, чтобы избежать проблем с огромными файлами.
    // Это предотвращает ошибку логики, когда width и height ограничивались независимо.
    size_t working_size = buf_size;
    const size_t max_grid_area = (size_t)MAX_GRID_DIM * MAX_GRID_DIM;
    if (working_size > max_grid_area) {
        working_size = max_grid_area;
    }

    if (working_size == 0) {
        // Нечего мутировать, просто возвращаем как есть (или 0, если *out_buf не установлен).
        // В данном случае AFL++ не вызовет нас с buf_size == 0, но проверка не помешает.
        *out_buf = buf;
        return buf_size;
    }

    // Вычисляем размеры сетки на основе рабочего размера
    int width = (int)sqrt((double)working_size);
    if (width <= 0) width = 1;

    int height = (working_size + width - 1) / width;
    if (height <= 0) height = 1;

    size_t total_cells = (size_t)width * height;

    // Перераспределяем память для сетки, если требуется
    if (total_cells > mutator->capacity) {
        free(mutator->grid_cur);
        free(mutator->grid_next);

        mutator->grid_cur = malloc(total_cells);
        mutator->grid_next = malloc(total_cells);

        // ИЗМЕНЕНО: Корректная обработка сбоя malloc
        if (!mutator->grid_cur || !mutator->grid_next) {
            free(mutator->grid_cur);
            free(mutator->grid_next);
            mutator->grid_cur = mutator->grid_next = NULL;
            mutator->capacity = 0;

            // Сообщаем AFL++, что мутация провалилась. НЕ возвращаем оригинальный буфер.
            return 0;
        }
        mutator->capacity = total_cells;
    }

    // Копируем входные данные в сетку, используя меньший из размеров
    size_t copy_size = (working_size < total_cells) ? working_size : total_cells;
    memcpy(mutator->grid_cur, buf, copy_size);
    if (total_cells > copy_size) {
        memset(mutator->grid_cur + copy_size, 0, total_cells - copy_size);
    }
    
    // Принудительный битфлип первого байта, чтобы гарантировать изменение
    mutator->grid_cur[0] ^= 1 << rand_below(mutator->afl, 8);

    // Несколько итераций мутации
    int num_iterations = 1 + rand_below(mutator->afl, 8);

    for (int iter = 0; iter < num_iterations; ++iter) {
        for (int r = 0; r < height; ++r) {
            for (int c = 0; c < width; ++c) {
                size_t idx = (size_t)r * width + c;

                // С вероятностью 1/4 — простой битфлип
                if (rand_below(mutator->afl, 4) == 0) {
                    mutator->grid_next[idx] = mutator->grid_cur[idx] ^ (1 << rand_below(mutator->afl, 8));
                } else {
                    // XOR-суммирование соседей в стиле игры "Жизнь"
                    uint8_t xor_sum = 0;
                    for (int dr = -1; dr <= 1; ++dr) {
                        for (int dc = -1; dc <= 1; ++dc) {
                            if (dr == 0 && dc == 0) continue;
                            int nr = (r + dr + height) % height;
                            int nc = (c + dc + width) % width;
                            xor_sum ^= mutator->grid_cur[(size_t)nr * width + nc];
                        }
                    }
                    mutator->grid_next[idx] = xor_sum;
                }
            }
        }

        // Меняем текущий и следующий слой местами для следующей итерации
        uint8_t *tmp = mutator->grid_cur;
        mutator->grid_cur = mutator->grid_next;
        mutator->grid_next = tmp;
    }

    // Формируем результат, ограничивая его максимальным размером
    size_t out_size = total_cells;
    if (out_size > max_size) {
        out_size = max_size;
    }

    // Выделяем память под выходной буфер
    uint8_t* out_buf_ptr = malloc(out_size);

    // ИЗМЕНЕНО: Корректная обработка сбоя malloc
    if (!out_buf_ptr) {
        // Сообщаем AFL++, что мутация провалилась
        return 0;
    }

    memcpy(out_buf_ptr, mutator->grid_cur, out_size);
    *out_buf = out_buf_ptr;

    return out_size;
}