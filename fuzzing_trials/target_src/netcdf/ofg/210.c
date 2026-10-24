#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vars_ushort(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned short *data);

int LLVMFuzzerTestOneInput_210(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for our parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Initialize parameters for nc_get_vars_ushort
    int ncid = (int)data[0]; // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid

    // Use the next bytes for start and count arrays
    size_t start[1];
    size_t count[1];
    start[0] = (size_t)data[2];
    count[0] = (size_t)data[3];

    // Use the next bytes for stride
    ptrdiff_t stride[1];
    stride[0] = (ptrdiff_t)data[4];

    // Allocate memory for data array
    unsigned short data_array[1];
    data_array[0] = (unsigned short)data[5];

    // Call the function-under-test
    nc_get_vars_ushort(ncid, varid, start, count, stride, data_array);

    return 0;
}