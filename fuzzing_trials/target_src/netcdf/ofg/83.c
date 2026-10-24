#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_set_base_pe(int, int);

// Fuzzing harness
int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));

    // Call the function-under-test
    nc_set_base_pe(param1, param2);

    return 0;
}