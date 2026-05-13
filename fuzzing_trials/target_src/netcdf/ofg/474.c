#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_varm_ushort(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, unsigned short *data);

int LLVMFuzzerTestOneInput_474(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 0;
    int varid = 0;
    size_t start[2] = {0, 0};
    size_t count[2] = {1, 1};
    ptrdiff_t stride[2] = {1, 1};
    ptrdiff_t imap[2] = {1, 1};
    unsigned short data_out[2] = {0, 0};

    // Ensure the size is sufficient for fuzzing
    if (size < 4) {
        return 0;
    }

    // Use the input data to modify the parameters
    ncid = (int)data[0];
    varid = (int)data[1];
    start[0] = (size_t)data[2];
    start[1] = (size_t)data[3];

    // Call the function-under-test
    nc_get_varm_ushort(ncid, varid, start, count, stride, imap, data_out);

    return 0;
}