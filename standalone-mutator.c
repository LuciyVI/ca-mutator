#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

// Определяем минимальную версию afl_state_t для совместимости с мутатором
typedef struct {
    uint32_t *rand_seed;
    uint32_t rand_cnt;
} afl_state_t;

// Размер кеша случайных чисел
#define HARNESS_RAND_CACHE_SIZE 256

// Хранилище случайных чисел
static uint32_t harness_actual_rand_values[HARNESS_RAND_CACHE_SIZE];

// Типы функций кастомного мутатора
typedef void* (*afl_custom_init_t)(afl_state_t *afl, unsigned int seed);
typedef size_t (*afl_custom_fuzz_t)(
    void *data,
    const unsigned char *buf, size_t buf_size,
    unsigned char **out_buf,
    unsigned char *add_buf, size_t add_buf_size,
    size_t max_size
);
typedef void (*afl_custom_deinit_t)(void *data);

// Печать данных в hex формате
static void print_hex(const unsigned char *data, size_t len, size_t max_print, const char *title) {
    printf("\n%s (len=%zu):\n", title, len);
    if (!data && len > 0) {
        printf("(NULL буфер)\n");
        return;
    }
    if (len == 0) {
        printf("(пустой буфер)\n");
        return;
    }

    size_t show = (len < max_print) ? len : max_print;
    for (size_t i = 0; i < show; ++i) {
        printf("%02x ", data[i]);
    }
    if (len > max_print) {
        printf("... (сокращено)");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Использование: %s <mutator.so> <input_file>\n", argv[0]);
        return 1;
    }

    const char *mutator_path = argv[1];
    const char *input_path = argv[2];

    // Загрузка .so библиотеки
    void *handle = dlopen(mutator_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Ошибка dlopen: %s\n", dlerror());
        return 1;
    }

    // Поиск функций
    afl_custom_init_t p_init = NULL;
    *(void**)(&p_init) = dlsym(handle, "afl_custom_init");

    afl_custom_fuzz_t p_fuzz = dlsym(handle, "afl_custom_fuzz");
    afl_custom_deinit_t p_deinit = dlsym(handle, "afl_custom_deinit");

    if (!p_fuzz) {
        fprintf(stderr, "Ошибка: Не найдена функция afl_custom_fuzz\n");
        dlclose(handle);
        return 1;
    }

    // Чтение входного файла
    FILE *f = fopen(input_path, "rb");
    if (!f) {
        perror("Ошибка открытия файла");
        dlclose(handle);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long f_size_long = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (f_size_long < 0 || (size_t)f_size_long > SIZE_MAX) {
        fprintf(stderr, "Неверный размер файла\n");
        fclose(f);
        dlclose(handle);
        return 1;
    }

    size_t input_size = (size_t)f_size_long;
    unsigned char *input_data = NULL;

    if (input_size > 0) {
        input_data = malloc(input_size);
        if (!input_data) {
            perror("Ошибка выделения памяти под входной буфер");
            fclose(f);
            dlclose(handle);
            return 1;
        }

        if (fread(input_data, 1, input_size, f) != input_size) {
            fprintf(stderr, "Ошибка чтения файла\n");
            free(input_data);
            fclose(f);
            dlclose(handle);
            return 1;
        }
    }

    fclose(f);

    // Инициализация ГСЧ
    unsigned int custom_seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    srand(custom_seed);

    for (int i = 0; i < HARNESS_RAND_CACHE_SIZE; ++i) {
        harness_actual_rand_values[i] = (uint32_t)rand();
    }

    // Создаем dummy_afl_state
    afl_state_t dummy_afl_state;
    dummy_afl_state.rand_seed = harness_actual_rand_values;
    dummy_afl_state.rand_cnt = 0;

    // Вызываем afl_custom_init
    void *mut_data = p_init ? p_init(&dummy_afl_state, custom_seed) : NULL;
    if (p_init && !mut_data) {
        fprintf(stderr, "Ошибка: afl_custom_init вернул NULL\n");
        if (input_data) free(input_data);
        dlclose(handle);
        return 1;
    }

    // Вывод исходных данных
    print_hex(input_data, input_size, 64, "Исходные данные");

    // Подготовка выходного буфера
    size_t max_out_size = (input_size * 2) + 1024;
    if (max_out_size == 0) max_out_size = 1024;

    unsigned char *mutated_buf = NULL;

    // Вызов afl_custom_fuzz
    size_t mutated_size = p_fuzz(
        mut_data,
        input_data, input_size,
        &mutated_buf,
        NULL, 0,
        max_out_size
    );

    // Вывод мутированных данных
    print_hex(mutated_buf, mutated_size, 64, "Мутированные данные");

    // Освобождение ресурсов
    if (mutated_buf) free(mutated_buf);
    if (input_data) free(input_data);
    if (p_deinit) p_deinit(mut_data);
    dlclose(handle);

    return 0;
}