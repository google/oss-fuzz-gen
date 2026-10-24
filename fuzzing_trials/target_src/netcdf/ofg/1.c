#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int nc_get_varm_ubyte(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, unsigned char *value);

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + 2) {
        return 0; // Ensure there's enough data for all parameters
    }

    int ncid = data[0];
    int varid = data[1];

    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[2];
    ptrdiff_t imap[2];

    // Initialize start and count arrays
    start[0] = (size_t)data[2];
    start[1] = (size_t)data[3];
    count[0] = (size_t)data[4];
    count[1] = (size_t)data[5];

    // Initialize stride and imap arrays
    stride[0] = (ptrdiff_t)data[6];
    stride[1] = (ptrdiff_t)data[7];
    imap[0] = (ptrdiff_t)data[8];
    imap[1] = (ptrdiff_t)data[9];

    // Allocate memory for the value array
    unsigned char value[2];
    value[0] = data[10];
    value[1] = data[11];

    // Call the function-under-test
    nc_get_varm_ubyte(ncid, varid, start, count, stride, imap, value);

    return 0;
}