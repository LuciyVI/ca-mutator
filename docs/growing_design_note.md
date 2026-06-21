# Growing CA design note (v1)

This file freezes the deterministic contract before code changes in `src/growing_engine.c`.

## 1. Cell representation (`growing_cell_t`)

Each cell stores:

- `byte_sum` (`uint16_t`) aggregate XOR checksum for block bytes
- `printable` (`uint8_t`) count of printable bytes in the block
- `filled` (`uint8_t`) number of valid bytes in the block
- `entropy` (`uint8_t`) block checksum accumulator
- `activity` (`uint8_t`) transition state for scheduling/mutation rank
- `channels[6]` (`uint16_t[]`) deterministic feature channels
- `position` (`size_t`) origin byte offset of the block

All channels are integer-only (no floating point).

## 2. Input encoding (`cell_features_encode`)

`grow_encode_cell(input_block, index)` performs:

1. Determine `[start, end)` block window.
2. Set `position = start`, `filled = end - start`.
3. Reset aggregate channels.
4. For each byte in block:
   - `byte_sum ^= byte`
   - `printable += is_printable(byte)` (`0x20..0x7E`)
   - `entropy = entropy + (byte ^ local_index)`
5. `activity` is derived deterministically from `byte_sum`, `printable`, and `entropy`.
6. `channels[k]` is initialized from deterministic bit-mixing of aggregates.

Values are saturated/truncated by underlying integer types.

## 3. Seed selection (`growing_select_seeds`)

No prefilter is required in v1: every block becomes one candidate mutation entry.
Candidate list is shuffled only by deterministic score ordering.

## 4. Update mask (`growing_build_update_mask`)

For every evolution step:

- For each cell `i`, sample `rand_below(100u)`.
- `update_mask[i] = sample < 60`.

This is an explicit 60% Bernoulli update probability.

## 5. Cell update (`growing_update_cell`)

For a cell with index `idx` and source snapshot `src`:

- Neighbor lookups at distances 1,2,4,8 use circular wrapping indices.
- Weighted accumulator:
  `weighted = 7*(n1_l+n1_r) + 3*(n2_l+n2_r) + 2*(n4_l+n4_r) + 1*(n8_l+n8_r)`.
- `activity` is updated by shifted weighted delta and clamped to `[0,255]`.
- `byte_sum`, `entropy`, and channel payloads are updated from `weighted`.

## 6. Update mode

v1 requires asynchronous-but-partially-synchronous update:

1. Copy `engine->cells` into `next`.
2. For indices with `update_mask[i]`, apply `growing_update_cell(src, idx, next)`.
3. Swap `cells` and `next` buffers.

This must **not** be in-place order-dependent mutation.

## 7. Steps and mutation budget

- `iterations = 1 + rand_below(5)` per `ca_growing_mutate`.
- `max_ops = clamp(1 + cell_count / 64, 1, 8)`.

## 8. Operations decoding (`growing_decode_operations`)

For each cell (after evolution), derive:

- `pos = position + (local_feature % filled)` when `filled > 0`.
- If zero-byte block appears (only possible via edge cases), allow only bounded insert.
- `kind` mapping:
  - `channels[1] % 6`
    - 0: `BIT_FLIP`
    - 1: `SET_BYTE`
    - 2: `ADD_BYTE`
    - 3: `SUB_BYTE`
    - 4: either `DELETE_RANGE` (if block can satisfy length) else fallback flip
    - 5: `INSERT_BYTES`
- `score = activity`
- `source_index = cell index`
- `len = 1` for point ops
- `INSERT_BYTES` lengths from channels with minimum 1.

Output bytes for `INSERT_BYTES` are sampled with:

- `rand_below(256)` per byte, number of times = decoded insertion length.

## 9. RNG contract

All calls use the injected `ca_rng_t`:

- `below(context, upper)` is required for `upper > 0`.
- If `upper == 0`, implementation returns `0` before delegating.
- There are no external RNG sources.

## 10. Mutation-plan limits

Decoder produces candidate operations; `mutation_plan` module performs:

- validation by input bounds,
- score-based acceptance,
- conflict resolution,
- sort by origin position,
- optional insertion-dropping to satisfy `max_output_len`,
- final deterministic apply.
