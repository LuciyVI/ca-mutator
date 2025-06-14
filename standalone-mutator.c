// Сохраните этот код как test_harness_iterative.c
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

#include "afl-fuzz.h"

typedef void* (*afl_custom_init_t)(afl_state_t *afl, unsigned int seed);
typedef size_t (*afl_custom_fuzz_t)(void*, uint8_t*, size_t, uint8_t**, uint8_t*, size_t, size_t);
typedef void (*afl_custom_post_process_t)(void*, uint8_t*, size_t, uint8_t*);
typedef void (*afl_custom_deinit_t)(void *data);

static void print_hex(const unsigned char *data, size_t len, const char *title) {
    printf("\n--- %s (длина=%zu) ---\n", title, len);
    if (!data || len == 0) { printf("(пусто)\n"); return; }
    size_t show = (len < 32) ? len : 32;
    for (size_t i = 0; i < show; ++i) printf("%02x ", data[i]);
    if (len > show) printf("...");
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Использование: %s <mutator.so> <input_file>\n", argv[0]);
        return 1;
    }
    const char *mutator_path = argv[1];
    const char *input_path = argv[2];

    void *handle = dlopen(mutator_path, RTLD_NOW);
    if (!handle) { fprintf(stderr, "Ошибка dlopen: %s\n", dlerror()); return 1; }

    afl_custom_init_t p_init = dlsym(handle, "afl_custom_init");
    afl_custom_fuzz_t p_fuzz = dlsym(handle, "afl_custom_fuzz");
    afl_custom_post_process_t p_post = dlsym(handle, "afl_custom_post_process");
    afl_custom_deinit_t p_deinit = dlsym(handle, "afl_custom_deinit");
    
    if (!p_fuzz || !p_init || !p_deinit || !p_post) {
        fprintf(stderr, "Ошибка: Не удалось найти функции init, fuzz, deinit, post_process\n");
        dlclose(handle); return 1;
    }

    FILE *f = fopen(input_path, "rb");
    if (!f) { perror("Ошибка открытия файла"); dlclose(handle); return 1; }
    fseek(f, 0, SEEK_END); size_t input_size = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *orig_input_data = malloc(input_size);
    if (!orig_input_data || fread(orig_input_data, 1, input_size, f) != input_size) {
        fprintf(stderr, "Ошибка чтения\n");
        fclose(f); dlclose(handle); free(orig_input_data); return 1;
    }
    fclose(f);

    // Создаем dummy afl_state для передачи в post_process
    afl_state_t *dummy_afl = calloc(1, sizeof(afl_state_t));
    if (!dummy_afl) { perror("calloc afl_state_t"); return 1; }
    dummy_afl->fsrv.map_size = 65536;
    dummy_afl->virgin_bits = malloc(dummy_afl->fsrv.map_size);
    memset(dummy_afl->virgin_bits, 0xFF, dummy_afl->fsrv.map_size);

    unsigned int seed = (unsigned int)time(NULL);
    // Передаем указатель на dummy_afl, но мутатор (в тестовом режиме) его не будет использовать
    void *mut_data = p_init(dummy_afl, seed); 
    
    print_hex(orig_input_data, input_size, "Оригинальный вход");
    
    int fuzz_iterations = 5;
    uint8_t *current_buf = orig_input_data;
    size_t current_size = input_size;
    uint8_t *match_bits = malloc(dummy_afl->fsrv.map_size);

    for (int i = 0; i < fuzz_iterations; ++i) {
        printf("\n================ Итерация #%d ================\n", i + 1);

        uint8_t *mutated_buf = NULL;
        size_t mutated_size = p_fuzz(mut_data, current_buf, current_size, &mutated_buf, NULL, 0, current_size * 2 + 1024);
        
        char title[100];
        sprintf(title, "Мутация #%d", i + 1);
        print_hex(mutated_buf, mutated_size, title);

        // Симулируем обратную связь: вызываем post_process
        // Поскольку в тестовой сборке мутатора эта функция пуста, вызов просто пройдет успешно
        // В реальном мутаторе здесь бы анализировался match_bits
        printf("...вызов post_process (в тестовом режиме он пустой)...\n");
        p_post(mut_data, mutated_buf, mutated_size, match_bits);

        // Передаем мутированный выход на вход следующей итерации
        if (current_buf != orig_input_data) free(current_buf);
        current_buf = mutated_buf;
        current_size = mutated_size;
    }


    printf("\n================ Завершение =================\n");
    if (current_buf != orig_input_data) free(current_buf);
    free(orig_input_data);
    free(match_bits);
    free(dummy_afl->virgin_bits);
    free(dummy_afl);
    p_deinit(mut_data);
    dlclose(handle);
    return 0;
}