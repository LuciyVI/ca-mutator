# AFL++ Custom Mutator: Cellular Automaton (XOR Neighbors)

This project implements a custom mutator for AFL++ based on a 2D Cellular Automaton (CA). The mutator transforms input data into a 2D grid and applies a simple CA rule for a random number of iterations to generate mutated test cases.

## Features

* **Cellular Automaton Mutation:** Uses a 2D CA to mutate input.
* **Dynamic Grid:** The input buffer is mapped to a 2D grid. Grid dimensions are calculated based on input size, aiming for a square-like structure.
* **XOR Sum Rule:** The state of each cell in the next generation is determined by the XOR sum of its 8 neighbors in the current generation.
* **Toroidal Grid:** The grid boundaries wrap around (toroidal array).
* **Random Iterations:** The CA evolves for a random number of iterations (1 to 8 by default), determined using AFL++'s random number generator.
* **Memory Management:** Grids are dynamically allocated and resized as needed, with a maximum dimension limit (`MAX_GRID_DIM`) to prevent excessive memory usage.
* **OpenMP Support:** The CA update loop can be parallelized using OpenMP if enabled during compilation.
* **AFL++ Integration:** Implements the required `afl_custom_init`, `afl_custom_deinit`, and `afl_custom_fuzz` functions for use with AFL++.
* **Fallback for `RAND_CACHE_SIZE`:** Provides a default value and a warning if `RAND_CACHE_SIZE` is not defined by AFL++ headers (e.g., if `config.h` is missing or doesn't define it).

## How it Works

1.  **Initialization (`afl_custom_init`):**
    * Allocates a state structure (`my_mutator_t`) to hold the AFL++ state and CA grids.

2.  **Deinitialization (`afl_custom_deinit`):**
    * Frees the allocated memory for the state structure and CA grids.

3.  **Fuzzing (`afl_custom_fuzz`):**
    * **Input Handling:**
        * If the input buffer (`buf`) is empty, it returns 0.
        * Calculates `width` and `height` for the 2D grid. `width` is roughly `sqrt(buf_size)`. `height` is calculated to accommodate all input bytes.
        * Dimensions are capped by `MAX_GRID_DIM` (default 256).
    * **Grid Allocation:**
        * If the required `total_cells` exceeds the current `grid_capacity`, the internal `grid_cur` and `grid_next` buffers are reallocated.
    * **Grid Population:**
        * The input buffer data is copied into `grid_cur`.
        * If `total_cells` is larger than `buf_size`, the remaining cells in `grid_cur` are padded with zeros.
    * **CA Iterations:**
        * A random number of iterations (`num_iterations_T`, between 1 and 8) is determined using `afl->rand_seed`.
        * The CA simulation runs for `num_iterations_T` steps:
            * For each cell `(r, c)` in `grid_cur`:
                * The states of its 8 neighbors are XORed together.
                * The result is stored in `grid_next[r * width + c]`.
                * Boundary conditions are toroidal (wrap-around).
            * After updating all cells, `grid_cur` and `grid_next` pointers are swapped.
    * **Output Generation:**
        * The content of the final `grid_cur` is copied to the output buffer (`*out_buf_ptr`).
        * The output size is `total_cells`, potentially truncated by `max_size` if provided by AFL++.
        * The output buffer is reallocated to the required `out_size`.

## Dependencies

* **AFL++:** This mutator is designed to be compiled as a shared library and used with AFL++.
* **C Compiler:** A C compiler that supports C99 and GNU/Clang extensions (like `__attribute__((unused))`, `__has_include`). GCC or Clang are recommended.
* **OpenMP (Optional):** If you want to use parallel processing for the CA updates, your compiler needs to support OpenMP, and you should compile with the appropriate flag (e.g., `-fopenmp`).

## Compilation

To compile this custom mutator as a shared library (e.g., `custom_ca_mutator.so`):

```bash
# Using GCC
gcc -shared -o custom_ca_mutator.so your_source_file.c -I/path/to/afl++/include $(afl-config --cflags) -O3 -Wall -Wextra -fPIC -fopenmp

# Using Clang
clang -shared -o custom_ca_mutator.so your_source_file.c -I/path/to/afl++/include $(afl-config --cflags) -O3 -Wall -Wextra -fPIC -fopenmp
