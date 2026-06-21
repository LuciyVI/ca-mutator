# ca-mutator

AFL++ custom mutator with pluggable engines:

- `ca_mutator_xor.so` — legacy `CA_OUTPUT_BUFFER` engine.
- `ca_mutator_growing.so` — `CA_OUTPUT_PLAN` engine with mutation-plan normalization and application in adapter.

The two shared libraries are built from the same common runtime and are isolated by build target.

## Current v1 design

- `src/ca_engine.c` exposes engine creation + `mutate`/`destroy`.
- `include/ca_engine.h` defines stable engine/result interfaces and RNG contract:
  - `ca_engine_create_*` receives an explicit `ca_rng_t`.
  - `ca_rng_t.below(ctx, upper)` must be called with `upper > 0`.
  - `CA_OUTPUT_BUFFER` and `CA_OUTPUT_PLAN` are distinct.
- `src/mutation_plan.c` implements validate/normalize/measure/apply pipeline for plan-based mutations.
- `src/afl_adapter.c` is the minimal required AFL++ interface:
  - `afl_custom_init`
  - `afl_custom_fuzz`
  - `afl_custom_describe`
  - `afl_custom_splice_optout`
  - `afl_custom_deinit`
- `src/afl_adapter.c` owns `plan_out_buf` for applying plans and uses `afl_realloc` when growing it.

### Ownership contract

- `CA_OUTPUT_BUFFER`:
  - returned buffer is a borrowed view from XOR engine.
  - lives until next `ca_engine_mutate` or engine destroy.
  - AFL adapter/standalone **must not free** it.
- `CA_OUTPUT_PLAN`:
  - normalized plan is owned by growing engine / mutation_plan arena.
  - adapter materializes output into its own `plan_out_buf` and returns that pointer.

### Zero-result / skip contract

- `ca_custom_fuzz` treats `return len == 0` as skip.
- XOR baseline still preserves legacy behavior for empty input (`1` byte when needed).
- Growing engine allows only `INSERT_BYTES(pos=0)` on empty input; with `max_output_len == 0` it returns `SKIP`.
- A plan that deletes the entire non-empty input is treated as skip in adapter (zero length output).

### Build

```bash
make ca_mutator_xor.so
make ca_mutator_growing.so
make standalone-mutator
```

Build uses pinned AFL++ headers via `AFL_INCLUDE` and does not rely on repository `afl-fuzz.h`.

## Notes

- `standalone-mutator` is intentionally minimal and loads any built shared object.
- Build script: `scripts/build_mutator.sh`
- Docker setup pins AFL++ commit in `builder.Dockerfile` and verifies it after checkout.
