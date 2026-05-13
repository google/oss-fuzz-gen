#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_vars_short(int, int, const size_t *, const size_t *, const ptrdiff_t *, short *);

int LLVMFuzzerTestOneInput_300(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough for our needs
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) + sizeof(short)) {
        return 0;
    }

    // Initialize parameters for nc_get_vars_short
    int ncid = (int)data[0];  // Example initialization
    int varid = (int)data[1]; // Example initialization

    // Allocate memory for start, count, stride, and value
    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[1];
    short value[1];

    // Copy data into start, count, stride, and value
    memcpy(start, data + 2, sizeof(size_t) * 2);
    memcpy(count, data + 2 + sizeof(size_t) * 2, sizeof(size_t) * 2);
    memcpy(stride, data + 2 + sizeof(size_t) * 4, sizeof(ptrdiff_t));
    memcpy(value, data + 2 + sizeof(size_t) * 4 + sizeof(ptrdiff_t), sizeof(short));

    // Ensure that count and stride are non-zero to avoid potential infinite loops or invalid memory access
    for (size_t i = 0; i < 2; i++) {
        if (count[i] == 0) {
            count[i] = 1; // Set to a minimum valid value
        }
    }
    if (stride[0] == 0) {
        stride[0] = 1; // Set to a minimum valid value
    }

    // Call the function-under-test
    nc_get_vars_short(ncid, varid, start, count, stride, value);

    return 0;
}