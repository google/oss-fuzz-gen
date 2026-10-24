#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function prototype for the function-under-test
int nc_get_vars_schar(int, int, const size_t *, const size_t *, const ptrdiff_t *, signed char *);

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + 2) {
        return 0;
    }

    // Initialize the first two integer parameters
    int param1 = (int)data[0];
    int param2 = (int)data[1];

    // Initialize size_t arrays for start and count
    size_t start[2];
    size_t count[2];

    // Copy data into start and count arrays
    memcpy(start, data + 2, sizeof(size_t) * 2);
    memcpy(count, data + 2 + sizeof(size_t) * 2, sizeof(size_t) * 2);

    // Initialize ptrdiff_t array for stride
    ptrdiff_t stride[2];

    // Copy data into stride array
    memcpy(stride, data + 2 + sizeof(size_t) * 4, sizeof(ptrdiff_t) * 2);

    // Calculate the remaining size for values array
    size_t values_size = size - (2 + sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2);

    // Check if there is enough data for at least one signed char value
    if (values_size < sizeof(signed char)) {
        return 0;
    }

    // Allocate memory for signed char array for values
    signed char *values = (signed char *)malloc(values_size);
    if (!values) {
        return 0;
    }

    // Copy data into values array
    memcpy(values, data + 2 + sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2, values_size);

    // Call the function-under-test
    nc_get_vars_schar(param1, param2, start, count, stride, values);

    // Free allocated memory
    free(values);

    return 0;
}