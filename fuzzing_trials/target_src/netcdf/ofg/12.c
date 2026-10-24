#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include this for memcpy if needed

// Assume this is the function-under-test, typically provided by an external library
int nc_get_vars_double(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, double *data);

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize all parameters
    if (size < sizeof(size_t) * 3 + sizeof(ptrdiff_t) + sizeof(double)) {
        return 0;
    }

    // Initialize the parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    double data_out[1];

    // Use the input data to initialize the parameters
    start[0] = (size_t)data[2];
    count[0] = (size_t)data[3];
    stride[0] = (ptrdiff_t)data[4];
    memcpy(&data_out[0], &data[5], sizeof(double)); // Use memcpy to safely copy the double value

    // Ensure count is not zero to avoid no-operation
    if (count[0] == 0) {
        count[0] = 1;
    }

    // Call the function-under-test
    nc_get_vars_double(ncid, varid, start, count, stride, data_out);

    return 0;
}