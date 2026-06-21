#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>

#include <afl-fuzz.h>

typedef void *(*afl_custom_init_t)(afl_state_t *afl, unsigned int seed);
typedef size_t (*afl_custom_fuzz_t)(void *, uint8_t *, size_t, uint8_t **,
                                    uint8_t *, size_t, size_t);
typedef const char *(*afl_custom_describe_t)(void *, size_t);
typedef void (*afl_custom_deinit_t)(void *data);

static void init_dummy_afl_rng(afl_state_t *afl, u64 seed) {
    if (!afl) return;
    if (seed == 0) {
        seed = 0x123456789abcdef0ull;
    }

    afl->rand_seed[0] = (AFL_RAND_RETURN)seed;
    afl->rand_seed[1] = (AFL_RAND_RETURN)(seed ^ 0x9e3779b97f4a7c15ull);
    afl->rand_seed[2] = (AFL_RAND_RETURN)(seed * 0x3c6ef372fe94f82bull + 1ull);
    afl->rand_cnt = 1024;
    afl->fixed_seed = 1;
}

static uint64_t mut_hash64(const uint8_t *data, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    const uint64_t p = 1099511628211ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)data[i];
        h *= p;
    }
    return h;
}

static void print_prefix_bytes(const uint8_t *data, size_t len) {
    size_t show = len < 32 ? len : 32;
    for (size_t i = 0; i < show; ++i) {
        printf("%02x ", data[i]);
    }
    if (len > show) {
        printf("...");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [--iterations N] <mutator.so> <input_file>\n",
                argv[0]);
        return 1;
    }

    size_t iterations = 5;
    u64 rng_seed = 0x123456789abcdef0ull;
    const char *mutator_path = NULL;
    const char *input_path = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--iterations") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr,
                        "Usage: %s [--iterations N] [--seed S] <mutator.so> <input_file>\n",
                        argv[0]);
                return 1;
            }
            iterations = (size_t)strtoull(argv[i + 1], NULL, 10);
            ++i;
            continue;
        }

        if (strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr,
                        "Usage: %s [--iterations N] [--seed S] <mutator.so> <input_file>\n",
                        argv[0]);
                return 1;
            }
            rng_seed = strtoull(argv[i + 1], NULL, 10);
            ++i;
            continue;
        }

        if (!mutator_path) {
            mutator_path = argv[i];
            continue;
        }

        if (!input_path) {
            input_path = argv[i];
            continue;
        }
    }

    if (!mutator_path || !input_path) {
        fprintf(stderr,
                "Usage: %s [--iterations N] [--seed S] <mutator.so> <input_file>\n",
                argv[0]);
        return 1;
    }

    bool is_growing =
        (strstr(mutator_path, "ca_mutator_growing") != NULL);
    bool error = false;
    size_t skips = 0;
    size_t noops = 0;
    size_t repeats = 0;
    size_t repeat_collision = 0;
    uint8_t *prev_data = NULL;
    size_t prev_len = 0;
    uint64_t prev_hash = 0;

    void *handle = dlopen(mutator_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    afl_custom_init_t init_fn =
        (afl_custom_init_t)dlsym(handle, "afl_custom_init");
    afl_custom_fuzz_t fuzz_fn =
        (afl_custom_fuzz_t)dlsym(handle, "afl_custom_fuzz");
    afl_custom_describe_t describe_fn =
        (afl_custom_describe_t)dlsym(handle, "afl_custom_describe");
    afl_custom_deinit_t deinit_fn =
        (afl_custom_deinit_t)dlsym(handle, "afl_custom_deinit");

    if (!init_fn || !fuzz_fn || !deinit_fn) {
        fprintf(stderr, "Missing required callbacks\n");
        dlclose(handle);
        return 1;
    }

    FILE *f = fopen(input_path, "rb");
    if (!f) {
        perror("fopen input");
        dlclose(handle);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t input_size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *orig_input = malloc(input_size);
    if (!orig_input || fread(orig_input, 1, input_size, f) != input_size) {
        fprintf(stderr, "Failed to read input file\n");
        free(orig_input);
        fclose(f);
        dlclose(handle);
        return 1;
    }
    fclose(f);

    afl_state_t *dummy_afl = calloc(1, sizeof(*dummy_afl));
    if (!dummy_afl) {
        free(orig_input);
        dlclose(handle);
        fprintf(stderr, "calloc failed\n");
        return 1;
    }
    dummy_afl->fsrv.map_size = 65536;
    dummy_afl->virgin_bits = malloc(dummy_afl->fsrv.map_size);
    if (!dummy_afl->virgin_bits) {
        free(orig_input);
        free(dummy_afl);
        dlclose(handle);
        fprintf(stderr, "failed to allocate dummy map\n");
        return 1;
    }
    memset(dummy_afl->virgin_bits, 0xFF, dummy_afl->fsrv.map_size);
    init_dummy_afl_rng(dummy_afl, rng_seed);

    void *mutator_state = init_fn(dummy_afl, (unsigned int)(rng_seed & 0xffffffffu));
    if (!mutator_state) {
        fprintf(stderr, "afl_custom_init failed\n");
        free(orig_input);
        free(dummy_afl->virgin_bits);
        free(dummy_afl);
        dlclose(handle);
        return 1;
    }

    if (describe_fn) {
        printf("Mutator describe: %s\n", describe_fn(mutator_state, 128));
    }

    uint8_t *current_buf = orig_input;
    size_t current_size = input_size;
    uint8_t *current_copy = NULL;

    for (size_t i = 0; i < iterations; ++i) {
        uint64_t input_hash = mut_hash64(current_buf, current_size);
        uint8_t *mutated = NULL;
        size_t max_size = current_size * 2u + 1024u;
        if (current_size > (SIZE_MAX - 1024u) / 2u) {
            max_size = SIZE_MAX;
        }

        size_t mutated_size =
            fuzz_fn(mutator_state, current_buf, current_size, &mutated, NULL, 0,
                    max_size);

        if (mutated != NULL && mutated == current_buf) {
            fprintf(stderr,
                    "ERROR: mutation %zu returned pointer to current input buffer\n",
                    i + 1);
            error = true;
            if (mutated_size == 0) {
                mutated = NULL;
            }
        }

        if (mutated_size == 0) {
            printf("\n--- mutation %zu: SKIP (in_len=%zu, in_hash=%016" PRIu64
                   ") ---\n",
                   i + 1, current_size, input_hash);
            ++skips;
            if (mutated != NULL) {
                fprintf(stderr,
                        "ERROR: mutation %zu returned non-null buffer on SKIP\n",
                        i + 1);
                error = true;
            }
            continue;
        }

        if (mutated == NULL) {
            fprintf(stderr, "ERROR: mutation %zu returned NULL with non-zero len\n",
                    i + 1);
            error = true;
            continue;
        }

        if (mutated_size > max_size) {
            fprintf(stderr,
                    "ERROR: mutation %zu output exceeds max_size (%zu > %zu)\n",
                    i + 1, mutated_size, max_size);
            error = true;
            break;
        }

        uint64_t hash = mut_hash64(mutated, mutated_size);
        int is_noop = 0;
        if (is_growing && current_size != 0 && mutated_size == current_size &&
            memcmp(mutated, current_buf, current_size) == 0) {
            is_noop = 1;
            ++noops;
            error = true;
        }

        if (is_noop) {
            printf("\n--- mutation %zu: NO-OP (len=%zu, in_len=%zu, in_hash=%016"
                   PRIu64 ", out_hash=%016" PRIu64 ") ---\n",
                   i + 1, mutated_size, current_size, input_hash, hash);
        } else {
            printf("\n--- mutation %zu: len=%zu (in_len=%zu, in_hash=%016"
                   PRIu64 ", out_hash=%016" PRIu64 ") ---\n",
                   i + 1, mutated_size, current_size, input_hash, hash);
        }
        print_prefix_bytes(mutated, mutated_size);

        if (!is_noop) {
            if (prev_data && prev_len == mutated_size && prev_hash == hash &&
                memcmp(prev_data, mutated, mutated_size) == 0) {
                printf("REPEAT_SAME_OUTPUT\n");
                ++repeats;
            } else if (prev_data && prev_hash == hash) {
                size_t common = prev_len < mutated_size ? prev_len : mutated_size;
                if (mutated_size != prev_len ||
                    memcmp(prev_data, mutated, common) != 0) {
                    printf("REPEAT_HASH_COLLISION\n");
                    ++repeat_collision;
                }
            }
        }

        if (is_noop) {
            if (mutated_size > 0) {
                printf("ERROR: no-op output should not be treated as successful mutation\n");
            }
            continue;
        }

        current_copy = (uint8_t *)malloc(mutated_size);
        if (!current_copy) {
            fprintf(stderr, "failed to allocate mutated copy\n");
            error = true;
            break;
        }
        memcpy(current_copy, mutated, mutated_size);

        if (current_buf != orig_input) {
            free(current_buf);
        }
        uint8_t *next_prev = (uint8_t *)malloc(mutated_size);
        if (!next_prev) {
            fprintf(stderr, "failed to allocate repeat tracker\n");
            error = true;
            break;
        }
        memcpy(next_prev, mutated, mutated_size);
        free(prev_data);
        prev_data = next_prev;
        prev_len = mutated_size;
        prev_hash = hash;

        current_buf = current_copy;
        current_size = mutated_size;
        current_copy = NULL;
    }

    if (prev_data) {
        free(prev_data);
    }
    if (current_buf != orig_input) {
        free(current_buf);
    }
    free(orig_input);
    deinit_fn(mutator_state);
    free(dummy_afl->virgin_bits);
    free(dummy_afl);
    fprintf(stderr,
            "mutator stats: skips=%zu noops=%zu repeats=%zu hash_collisions=%zu\n",
            skips, noops, repeats, repeat_collision);
    dlclose(handle);
    if (error) return 1;
    return 0;
}
