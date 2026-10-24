#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vars_long(int, int, const size_t *, const size_t *, const ptrdiff_t *, long *);

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for nc_get_vars_long
    int ncid = 1; // Example non-zero integer for netCDF ID
    int varid = 1; // Example non-zero integer for variable ID

    // Ensure size is large enough to extract necessary data
    if (size < 3 * sizeof(size_t) + sizeof(ptrdiff_t) + sizeof(long)) {
        return 0;
    }

    // Extract size_t values from the data
    size_t start[1];
    size_t count[1];
    size_t stride[1];
    start[0] = *((size_t *)data);
    count[0] = *((size_t *)(data + sizeof(size_t)));
    stride[0] = *((size_t *)(data + 2 * sizeof(size_t)));

    // Extract ptrdiff_t value from the data
    ptrdiff_t imap[1];
    imap[0] = *((ptrdiff_t *)(data + 3 * sizeof(size_t)));

    // Extract long value from the data
    long value[1];
    value[0] = *((long *)(data + 3 * sizeof(size_t) + sizeof(ptrdiff_t)));

    // Call the function-under-test
    nc_get_vars_long(ncid, varid, start, count, imap, value);

    return 0;
}