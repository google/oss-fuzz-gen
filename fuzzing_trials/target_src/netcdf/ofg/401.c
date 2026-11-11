#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the function is declared in a header file
// int nc_get_var1(int, int, const size_t *, void *);

int nc_get_var1(int, int, const size_t *, void *);

int LLVMFuzzerTestOneInput_401(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract two integers from the input data
    int param1 = *((int*)data);
    int param2 = *((int*)(data + sizeof(int)));

    // Extract a size_t value from the input data
    const size_t *param3 = (const size_t *)(data + sizeof(int) * 2);

    // Allocate memory for the void pointer parameter
    void *param4 = malloc(10); // Allocate 10 bytes for the sake of example

    if (param4 == NULL) {
        return 0; // If memory allocation fails, exit
    }

    // Call the function-under-test
    int result = nc_get_var1(param1, param2, param3, param4);

    // Free allocated memory
    free(param4);

    return 0;
}