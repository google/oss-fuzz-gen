#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize variables
    int ncid = 0;  // NetCDF file ID
    int varid = 0; // Variable ID
    const size_t ndims = 3; // Assume 3 dimensions for simplicity
    size_t start[ndims];
    size_t count[ndims];
    ptrdiff_t stride[ndims];
    char *text;

    // Ensure the input size is sufficient for our needs
    if (size < ndims * sizeof(size_t) + ndims * sizeof(ptrdiff_t) + 1) {
        return 0;
    }

    // Extract start, count, and stride from the input data
    memcpy(start, data, ndims * sizeof(size_t));
    memcpy(count, data + ndims * sizeof(size_t), ndims * sizeof(size_t));
    memcpy(stride, data + 2 * ndims * sizeof(size_t), ndims * sizeof(ptrdiff_t));

    // Allocate and copy text data
    text = (char *)malloc(size - (2 * ndims * sizeof(size_t) + ndims * sizeof(ptrdiff_t)));
    if (text == NULL) {
        return 0;
    }
    memcpy(text, data + 2 * ndims * sizeof(size_t) + ndims * sizeof(ptrdiff_t), size - (2 * ndims * sizeof(size_t) + ndims * sizeof(ptrdiff_t)));

    // Call the function-under-test
    nc_put_vars_text(ncid, varid, start, count, stride, text);

    // Free allocated memory
    free(text);

    return 0;
}