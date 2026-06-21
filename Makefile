CC ?= gcc

ROOT_DIR := $(CURDIR)
INCLUDE_DIR := include

AFLPP_DIR ?= /afl
ifdef AFL_INCLUDE
AFLPP_DIR := $(patsubst %/include/,%,$(patsubst %/include,%,$(AFL_INCLUDE)))
endif

PROJECT_CPPFLAGS := -I$(ROOT_DIR)/$(INCLUDE_DIR)
AFLPP_CPPFLAGS := -I$(AFLPP_DIR)/include

CFLAGS += -std=c11 -O2 -fPIC -Wall -Wextra -fno-omit-frame-pointer
CFLAGS += -MMD -MP

LDFLAGS_SHARED ?= -shared -Wl,-soname,$@
LDFLAGS_EXE ?= -rdynamic

SRC_DIR := src

SO_COMMON_SRCS := $(SRC_DIR)/ca_engine.c $(SRC_DIR)/mutation_plan.c \
	$(SRC_DIR)/afl_rand_next.c
XOR_SRCS := $(SO_COMMON_SRCS) $(SRC_DIR)/xor_engine.c $(SRC_DIR)/afl_adapter.c
GROWING_SRCS := $(SO_COMMON_SRCS) $(SRC_DIR)/growing_engine.c $(SRC_DIR)/afl_adapter.c

XOR_SO := ca_mutator_xor.so
GROWING_SO := ca_mutator_growing.so
STANDALONE := standalone-mutator

all: $(XOR_SO) $(GROWING_SO) $(STANDALONE)
STANDALONE_SRCS := standalone-mutator.c $(SRC_DIR)/afl_rand_next.c

TEST_XOR_NAME := test_xor_differential
TEST_XOR_SRCS := tests/test_xor_differential.c tests/legacy_xor_reference.c tests/table_rng.c
TEST_XOR_SRCS += $(SRC_DIR)/ca_engine.c $(SRC_DIR)/mutation_plan.c $(SRC_DIR)/xor_engine.c $(SRC_DIR)/growing_engine.c

TEST_GROWING_COMMON_SRCS := tests/growing_test_support.c tests/table_rng.c
TEST_GROWING_COMMON_SRCS += $(SRC_DIR)/ca_engine.c $(SRC_DIR)/mutation_plan.c $(SRC_DIR)/growing_engine.c
TEST_GROWING_DET_NAME := test_growing_determinism
TEST_GROWING_RNG_NAME := test_growing_rng_progress
TEST_GROWING_NOOP_NAME := test_growing_noop
TEST_GROWING_REUSE_NAME := test_growing_reuse
TEST_GROWING_MAX_SIZE_NAME := test_growing_max_size
TEST_GROWING_RESET_NAME := test_growing_plan_reset

$(TEST_XOR_NAME): $(TEST_XOR_SRCS)
	$(CC) $(CFLAGS) $(PROJECT_CPPFLAGS) -o $@ $^

$(TEST_GROWING_DET_NAME): tests/test_growing_determinism.c $(TEST_GROWING_COMMON_SRCS)
	$(CC) $(CFLAGS) -DCA_ENGINE_VARIANT=2 $(PROJECT_CPPFLAGS) -o $@ $^

$(TEST_GROWING_RNG_NAME): tests/test_growing_rng_progress.c $(TEST_GROWING_COMMON_SRCS)
	$(CC) $(CFLAGS) -DCA_ENGINE_VARIANT=2 $(PROJECT_CPPFLAGS) -o $@ $^

$(TEST_GROWING_NOOP_NAME): tests/test_growing_noop.c $(TEST_GROWING_COMMON_SRCS)
	$(CC) $(CFLAGS) -DCA_ENGINE_VARIANT=2 $(PROJECT_CPPFLAGS) -o $@ $^

$(TEST_GROWING_REUSE_NAME): tests/test_growing_reuse.c $(TEST_GROWING_COMMON_SRCS)
	$(CC) $(CFLAGS) -DCA_ENGINE_VARIANT=2 $(PROJECT_CPPFLAGS) -o $@ $^

$(TEST_GROWING_MAX_SIZE_NAME): tests/test_growing_max_size.c $(TEST_GROWING_COMMON_SRCS)
	$(CC) $(CFLAGS) -DCA_ENGINE_VARIANT=2 $(PROJECT_CPPFLAGS) -o $@ $^

$(TEST_GROWING_RESET_NAME): tests/test_growing_plan_reset.c $(TEST_GROWING_COMMON_SRCS)
	$(CC) $(CFLAGS) -DCA_ENGINE_VARIANT=2 $(PROJECT_CPPFLAGS) -o $@ $^

$(XOR_SO): $(XOR_SRCS) | check-aflpp
	$(CC) $(CFLAGS) $(PROJECT_CPPFLAGS) $(AFLPP_CPPFLAGS) \
		-DCA_ENGINE_VARIANT=1 -o $@ $(LDFLAGS_SHARED) $^

$(GROWING_SO): $(GROWING_SRCS) | check-aflpp
	$(CC) $(CFLAGS) $(PROJECT_CPPFLAGS) $(AFLPP_CPPFLAGS) \
		-DCA_ENGINE_VARIANT=2 -o $@ $(LDFLAGS_SHARED) $^

$(STANDALONE): $(STANDALONE_SRCS) | check-aflpp
	$(CC) $(CFLAGS) $(PROJECT_CPPFLAGS) $(AFLPP_CPPFLAGS) -o $@ $(LDFLAGS_EXE) $^ -ldl

test-xor: $(TEST_XOR_NAME)

test-growing: \
	$(TEST_GROWING_DET_NAME) \
	$(TEST_GROWING_RNG_NAME) \
	$(TEST_GROWING_NOOP_NAME) \
	$(TEST_GROWING_REUSE_NAME) \
	$(TEST_GROWING_MAX_SIZE_NAME) \
	$(TEST_GROWING_RESET_NAME)

test-growing-run: test-growing
	./$(TEST_GROWING_DET_NAME)
	./$(TEST_GROWING_RNG_NAME)
	./$(TEST_GROWING_NOOP_NAME)
	./$(TEST_GROWING_REUSE_NAME)
	./$(TEST_GROWING_MAX_SIZE_NAME)
	./$(TEST_GROWING_RESET_NAME)

-include $(XOR_SRCS:.c=.d)
-include $(GROWING_SRCS:.c=.d)
-include $(TEST_XOR_SRCS:.c=.d)
-include $(TEST_GROWING_DET_NAME:=.d)
-include $(TEST_GROWING_RNG_NAME:=.d)
-include $(TEST_GROWING_NOOP_NAME:=.d)
-include $(TEST_GROWING_REUSE_NAME:=.d)
-include $(TEST_GROWING_MAX_SIZE_NAME:=.d)
-include $(TEST_GROWING_RESET_NAME:=.d)

clean:
	$(RM) \
		$(XOR_SO) \
		$(GROWING_SO) \
		$(STANDALONE) \
		$(TEST_XOR_NAME) \
		*.d \
		src/*.d \
		tests/*.d

.PHONY: all clean test-xor test-growing test-growing-run check-aflpp

check-aflpp:
	@test -f "$(AFLPP_DIR)/include/afl-fuzz.h" || \
		{ echo "error: $(AFLPP_DIR)/include/afl-fuzz.h not found"; \
		  echo "usage: make AFLPP_DIR=/path/to/AFLplusplus <target>"; \
		  exit 1; }
	@test -f "$(AFLPP_DIR)/include/alloc-inl.h" || \
		{ echo "error: $(AFLPP_DIR)/include/alloc-inl.h not found"; \
		  exit 1; }
