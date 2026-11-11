#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int nc_get_varm_uchar(int, int, const size_t *, const size_t *, const ptrdiff_t *, const ptrdiff_t *, unsigned char *);

int LLVMFuzzerTestOneInput_407(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + 2) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = data[0];
    int varid = data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];

    // Initialize start, count, stride, and imap arrays
    start[0] = (size_t)data[2];
    count[0] = (size_t)data[3];
    stride[0] = (ptrdiff_t)data[4];
    imap[0] = (ptrdiff_t)data[5];

    // Allocate memory for value
    unsigned char value[1];
    value[0] = data[6];

    // Call the function-under-test
    nc_get_varm_uchar(ncid, varid, start, count, stride, imap, value);

    return 0;
}