#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_varm_longlong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, long long *data);

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Define and initialize variables
    int ncid = 1;  // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure size is sufficient for our needs
    if (size < 4 * sizeof(size_t) + 2 * sizeof(ptrdiff_t) + sizeof(long long)) {
        return 0;
    }

    // Initialize start, count, stride, and imap arrays
    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[2];
    ptrdiff_t imap[2];
    long long data_out[1];

    // Fill arrays with data from the input
    memcpy(start, data, 2 * sizeof(size_t));
    memcpy(count, data + 2 * sizeof(size_t), 2 * sizeof(size_t));
    memcpy(stride, data + 4 * sizeof(size_t), 2 * sizeof(ptrdiff_t));
    memcpy(imap, data + 4 * sizeof(size_t) + 2 * sizeof(ptrdiff_t), 2 * sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_get_varm_longlong(ncid, varid, start, count, stride, imap, data_out);

    return 0;
}