#include <stddef.h>
#include <stdint.h>

// Assuming the function is declared in a header file
int nc_get_var_chunk_cache(int, int, size_t *, size_t *, float *);

int LLVMFuzzerTestOneInput_480(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int param1 = 1;  // Example initialization, can be varied
    int param2 = 1;  // Example initialization, can be varied

    // Ensure the size is sufficient to extract size_t and float values
    if (size < sizeof(size_t) * 2 + sizeof(float)) {
        return 0;
    }

    // Initialize size_t pointers
    size_t size_t_val1 = *((size_t *)(data));
    size_t size_t_val2 = *((size_t *)(data + sizeof(size_t)));

    // Initialize float pointer
    float float_val = *((float *)(data + sizeof(size_t) * 2));

    // Call the function with initialized parameters
    int result = nc_get_var_chunk_cache(param1, param2, &size_t_val1, &size_t_val2, &float_val);

    // Optionally, handle the result if needed
    (void)result;  // Suppress unused variable warning

    return 0;
}