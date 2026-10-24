#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int nc_get_varm_int(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, int *data);

int LLVMFuzzerTestOneInput_209(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(int) * 2) {
        return 0;
    }

    // Initialize parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];
    int output_data[1];

    // Assign values from the input data
    start[0] = (size_t)data[2];
    count[0] = (size_t)data[3];
    stride[0] = (ptrdiff_t)data[4];
    imap[0] = (ptrdiff_t)data[5];
    output_data[0] = (int)data[6];

    // Call the function-under-test
    nc_get_varm_int(ncid, varid, start, count, stride, imap, output_data);

    return 0;
}