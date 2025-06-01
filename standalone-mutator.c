#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>      // Для dlopen, dlsym, dlclose
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>     // Для getpid
#include <time.h>       // Для time()

// Определяем размер кеша для случайных чисел в тестовой обвязке.
// В идеале, он должен совпадать или быть больше, чем ожидает мутатор.
// Предоставленный мутатор имеет запасное значение 256 для RAND_CACHE_SIZE.
#define HARNESS_RAND_CACHE_SIZE 256

// Искусственная структура для имитации частей afl_state_t, используемых ГСЧ мутатора.
// Основываясь на типичной afl_state_t, afl->rand_seed является указателем.
typedef struct {
    uint32_t *rand_seed; // Указатель на массив случайных чисел
    uint32_t rand_cnt;   // Текущий индекс в массиве rand_seed
    uint32_t rand_size;  // Размер массива rand_seed (для полноты, хотя этим мутатором не используется)
    // Добавьте сюда другие поля, если ваш мутатор использует больше частей afl_state_t,
    // стараясь поддерживать структуру, совместимую с настоящей afl_state_t.
} fake_afl_state_minimal_rng_t;

// Фактическое хранилище для случайных чисел, используемых fake_afl_state
static uint32_t harness_actual_rand_values[HARNESS_RAND_CACHE_SIZE];

// Определения типов для функций кастомного мутатора
// Примечание: первый аргумент afl_custom_init изменен на void* для гибкости,
// так как тестовая обвязка предоставляет кастомную минимальную структуру.
typedef void* (*afl_custom_init_t)(void *afl, unsigned int seed);

// Сигнатура для afl_custom_fuzz, основанная на новых версиях AFL++
typedef size_t (*afl_custom_fuzz_t)(
    void *data,
    const unsigned char *buf, size_t buf_size,
    unsigned char **out_buf,
    unsigned char *add_buf, size_t add_buf_size,
    size_t max_size
);

typedef void (*afl_custom_deinit_t)(void *data);

// Печатает часть данных (до max_print байт) в шестнадцатеричном формате.
static void print_hex(const unsigned char *data, size_t len, size_t max_print, const char *title) {
    printf("\n%s (len=%zu):\n", title, len);
    if (data == NULL && len > 0) {
        printf("(NULL буфер с len > 0)\n");
        return;
    }
    if (data == NULL && len == 0) {
        printf("(NULL буфер, len 0 - обычно нормально для пустого вывода)\n");
        return;
    }
     if (len == 0) {
        printf("(пустой буфер)\n");
        return;
    }

    size_t show = (len < max_print) ? len : max_print;
    for (size_t i = 0; i < show; i++) {
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

    // 1) Загружаем библиотеку мутатора
    void *handle = dlopen(mutator_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Ошибка dlopen для %s: %s\n", mutator_path, dlerror());
        return 1;
    }

    // 2) Находим функции кастомного мутатора
    afl_custom_init_t p_init = (afl_custom_init_t)dlsym(handle, "afl_custom_init");
    if (dlerror() != NULL && !p_init) { // Проверяем dlerror после dlsym, если результат NULL
         fprintf(stderr, "Предупреждение: Не удалось найти afl_custom_init: %s\n", dlerror());
         // Продолжаем, но init может быть необязательным для некоторых мутаторов, если они не управляют состоянием.
         // Однако, этот конкретный CA-мутатор требует init.
    }

    afl_custom_fuzz_t p_fuzz = (afl_custom_fuzz_t)dlsym(handle, "afl_custom_fuzz");
     if (dlerror() != NULL && !p_fuzz) {
        fprintf(stderr, "Ошибка: Не удалось найти afl_custom_fuzz: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    afl_custom_deinit_t p_deinit = (afl_custom_deinit_t)dlsym(handle, "afl_custom_deinit");
    if (dlerror() != NULL && !p_deinit) {
        fprintf(stderr, "Предупреждение: Не удалось найти afl_custom_deinit: %s\n", dlerror());
        // Продолжаем, deinit может быть необязательным. Этот CA-мутатор его использует.
    }
    
    // Проверка основных функций
    if (!p_init || !p_fuzz || !p_deinit) {
        fprintf(stderr, "Одна или несколько обязательных функций мутатора (init, fuzz, deinit) отсутствуют!\n");
        dlclose(handle);
        return 1;
    }


    // 3) Читаем входной файл
    FILE *f = fopen(input_path, "rb");
    if (!f) {
        perror("Ошибка fopen");
        dlclose(handle);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long f_size_long = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (f_size_long < 0) {
        perror("Ошибка ftell");
        fclose(f);
        dlclose(handle);
        return 1;
    }
    if (f_size_long == 0) {
        printf("Предупреждение: Входной файл пуст.\n");
    }

    size_t input_size = (size_t)f_size_long;
    unsigned char *input_data = NULL;
    if (input_size > 0) {
        input_data = malloc(input_size);
        if (!input_data) {
            fprintf(stderr, "Ошибка malloc для input_data\n");
            fclose(f);
            dlclose(handle);
            return 1;
        }
        if (fread(input_data, 1, input_size, f) != input_size) {
            fprintf(stderr, "Ошибка чтения содержимого файла.\n");
            free(input_data);
            fclose(f);
            dlclose(handle);
            return 1;
        }
    }
    fclose(f);

    unsigned int custom_seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    // 4) Инициализируем поддельное состояние AFL для ГСЧ и вызываем init мутатора
    fake_afl_state_minimal_rng_t dummy_afl_rng_state;
    memset(&dummy_afl_rng_state, 0, sizeof(fake_afl_state_minimal_rng_t));

    // Указываем на наш статический массив для случайных чисел
    dummy_afl_rng_state.rand_seed = harness_actual_rand_values;
    dummy_afl_rng_state.rand_cnt = 0;
    dummy_afl_rng_state.rand_size = HARNESS_RAND_CACHE_SIZE;

    // Заполняем массив случайных чисел
    srand(custom_seed); // Инициализируем ГСЧ стандартной библиотеки C
    for (int i = 0; i < HARNESS_RAND_CACHE_SIZE; ++i) {
        harness_actual_rand_values[i] = (uint32_t)rand();
    }

    void *mut_data = p_init((void*)&dummy_afl_rng_state, custom_seed);
    if (!mut_data) {
        fprintf(stderr, "afl_custom_init завершился ошибкой!\n");
        if (input_data) free(input_data);
        dlclose(handle);
        return 1;
    }

    // 5) Печатаем исходные данные
    print_hex(input_data, input_size, 64, "Исходные данные");

    // 6) Вызываем afl_custom_fuzz
    //    - Передаем const unsigned char *buf
    //    - Передаем unsigned char **out_buf
    //    - Определяем разумный max_size для вывода.
    size_t max_fuzz_out_size = (input_size * 2) + 1024; // Пример максимального размера
    if (max_fuzz_out_size == 0 && input_size == 0) max_fuzz_out_size = 1024; // гарантируем некоторое место, если входной размер 0

    unsigned char *mutated_buf = NULL; // Ожидается, что мутатор выделит память для этого через *out_buf

    size_t mutated_size = p_fuzz(
        mut_data,
        input_data, input_size,    // Входной буфер и его размер
        &mutated_buf,              // Адрес указателя на выходной буфер
        NULL, 0,                   // Дополнительный буфер (add_buf) - не используется этим мутатором
        max_fuzz_out_size          // Максимальный размер для мутированных выходных данных
    );

    // 7) Печатаем мутированный результат
    print_hex(mutated_buf, mutated_size, 64, "Мутированные данные");

    // 8) Освобождаем ресурсы
    if (mutated_buf) {
        // В реальном сценарии AFL++ этим буфером управляет AFL, если он выделен через ck_alloc.
        // Поскольку кастомный CA-мутатор использует realloc(*out_buf_ptr, ...),
        // и *out_buf_ptr изначально был NULL (из mutated_buf = NULL),
        // realloc ведет себя как malloc. Поэтому мы должны освободить его здесь, в автономной утилите.
        free(mutated_buf);
    }
    if (input_data) {
        free(input_data);
    }
    p_deinit(mut_data);
    dlclose(handle);

    return 0;
}