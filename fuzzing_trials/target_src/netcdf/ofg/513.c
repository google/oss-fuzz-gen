#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_vars(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, void *data);

int LLVMFuzzerTestOneInput_513(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + 1) {
        // Ensure there is enough data for start, count, stride, and at least 1 byte for data
        return 0;
    }

    // Extracting parameters from the fuzzing data
    int ncid = data[0]; // Use the first byte for ncid
    int varid = data[1]; // Use the second byte for varid

    // Use the next bytes for start and count arrays
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];

    // Ensure data is not NULL by assigning at least one byte
    void *data_ptr = (void *)&data[sizeof(size_t) * 2 + sizeof(ptrdiff_t)];

    // Assign values to start, count, and stride
    start[0] = *(size_t *)&data[2];
    count[0] = *(size_t *)&data[2 + sizeof(size_t)];
    stride[0] = *(ptrdiff_t *)&data[2 + sizeof(size_t) * 2];

    // Call the function-under-test
    nc_get_vars(ncid, varid, start, count, stride, data_ptr);

    return 0;
}