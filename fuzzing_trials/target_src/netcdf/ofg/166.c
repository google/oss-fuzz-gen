#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int nc_put_varm_string(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const char **data);

int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract necessary parameters
    if (size < 20) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[2];
    ptrdiff_t imap[2];

    // Initialize start, count, stride, and imap arrays
    start[0] = (size_t)data[2];
    start[1] = (size_t)data[3];
    count[0] = (size_t)data[4];
    count[1] = (size_t)data[5];
    stride[0] = (ptrdiff_t)data[6];
    stride[1] = (ptrdiff_t)data[7];
    imap[0] = (ptrdiff_t)data[8];
    imap[1] = (ptrdiff_t)data[9];

    // Prepare a string array for the data parameter
    const char *strings[2];
    strings[0] = "fuzz_string_1";
    strings[1] = "fuzz_string_2";

    // Call the function-under-test
    nc_put_varm_string(ncid, varid, start, count, stride, imap, strings);

    return 0;
}