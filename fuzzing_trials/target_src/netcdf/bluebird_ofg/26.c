#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include string.h for memcpy

extern int nc_put_varm_longlong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const long long *op);

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Define variables for the function parameters
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure size is large enough to extract required data
    if (size < 6 * sizeof(size_t) + 2 * sizeof(ptrdiff_t) + sizeof(long long)) {
        return 0;
    }

    // Initialize start, count, stride, imap, and op
    size_t start[2];
    size_t count[2];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];
    long long op[1];

    // Copy data into the variables
    memcpy(start, data, 2 * sizeof(size_t));
    memcpy(count, data + 2 * sizeof(size_t), 2 * sizeof(size_t));
    memcpy(stride, data + 4 * sizeof(size_t), sizeof(ptrdiff_t));
    memcpy(imap, data + 4 * sizeof(size_t) + sizeof(ptrdiff_t), sizeof(ptrdiff_t));
    memcpy(op, data + 4 * sizeof(size_t) + 2 * sizeof(ptrdiff_t), sizeof(long long));

    // Call the function-under-test
    nc_put_varm_longlong(ncid, varid, (const size_t *)start, (const size_t *)count, (const ptrdiff_t *)stride, (const ptrdiff_t *)imap, (const long long *)op);

    return 0;
}