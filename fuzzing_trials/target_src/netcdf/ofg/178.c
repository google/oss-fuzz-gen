#include <stdint.h>
#include <stddef.h>

// Assuming the function nc_get_var is declared in some header file
// If the actual header file is available, include it instead
// #include "nc_header.h"

// Mock function signature for nc_get_var
int nc_get_var(int arg1, int arg2, void *arg3);

int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract two integers from the data
    int arg1 = *((int *)data);
    int arg2 = *((int *)(data + sizeof(int)));

    // Use the remaining data as the void pointer
    void *arg3 = (void *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var(arg1, arg2, arg3);

    return 0;
}