# IMPLEMENTATION PLAN v1 (normative contract)

## 1) RNG injection

- Engine creation signature is explicit:
  - `ca_status_t ca_engine_create_* (const ca_engine_config_t *config, ca_rng_t rng, ca_engine_t **out_engine)`
- `ca_rng_t` is injected through API and used by both engines.
- Contract:
  - `rng.context` must outlive engine.
  - `upper_bound > 0` when calling `below`.
  - Returned random values must be in `[0, upper_bound)`.
- `mutation_id` is kept as diagnostics only in v1.

## 2) Buffer ownership

- `CA_OUTPUT_BUFFER` is a borrowed view from XOR engine.
  - Adapter/standalone do not own and do not free it.
  - Valid until next mutate or engine destroy.
- `CA_OUTPUT_PLAN` is owned by growing engine as mutation-plan arena.
  - Adapter normalizes and applies immediately into `plan_out_buf`.
  - Adapter-owned `plan_out_buf` is reallocated with `afl_realloc`.
- `standalone-mutator` does not free pointer returned by `afl_custom_fuzz`.

## 3) Zero-length semantics

- In AFL++ context, returned length `0` is treated as skip.
- XOR on empty input keeps legacy behavior: produces one random byte.
- Growing on empty input:
  - allowed operation set is `INSERT_BYTES(pos=0)`;
  - if `max_output_len == 0`, engine/adater returns skip.
- Plan deleting all non-empty input is valid at mutation level but mapped to skip in adapter output.

## 4) Mutation operation schema

- Supported v1 operations:
  - `CA_OP_BIT_FLIP`
  - `CA_OP_SET_BYTE`
  - `CA_OP_ADD_BYTE`
  - `CA_OP_SUB_BYTE`
  - `CA_OP_DELETE_RANGE`
  - `CA_OP_INSERT_BYTES`
- Semantics:
  - point operations require `len == 1`.
  - `INSERT_BYTES` uses `len == data_len > 0`.
  - positions and ranges are validated against input length before normalization.

## 5) `max_size` policy

- Length is computed from accepted plan before materialization:
  - `result_len = input_len - deleted_len + inserted_len`.
- If too large:
  - remove insert operations with smallest score (lowest first; tie by source order) until within limit.
  - if still over limit with no insertions, return `CA_STATUS_OUTPUT_TOO_LARGE` (adapter maps to skip).
- No silent truncation.
- Overflow checks are explicit with checked `size_add_overflow` / `size_sub_underflow` helpers.

## 6) AFL headers

- Only `src/afl_adapter.c` and `standalone-mutator.c` include `afl-fuzz.h`.
- Build includes pinned AFL++ include path first and does not use repository-local AFL header copy.

## Engine variant split

- Two artifacts built separately:
  - `make ca_mutator_xor.so`
  - `make ca_mutator_growing.so`
- Shared build logic in common objects (`ca_engine.c`, `mutation_plan.c`), variant-specific C source selected by `CA_ENGINE_VARIANT`.
