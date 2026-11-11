#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assume this function is part of an external library
extern int nc_put_varm_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const unsigned long long *op);

int LLVMFuzzerTestOneInput_494(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned long long)) {
        return 0;
    }

    // Extract ncid and varid from the input data
    int ncid;
    int varid;
    memcpy(&ncid, data, sizeof(int));
    memcpy(&varid, data + sizeof(int), sizeof(int));

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];
    unsigned long long op[1];

    // Extract the rest of the parameters from the input data
    memcpy(start, data + sizeof(int) * 2, sizeof(size_t));
    memcpy(count, data + sizeof(int) * 2 + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + sizeof(int) * 2 + sizeof(size_t) * 2, sizeof(ptrdiff_t));
    memcpy(imap, data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t), sizeof(ptrdiff_t));
    memcpy(op, data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2, sizeof(unsigned long long));

    // Ensure that the parameters are non-trivial to increase code coverage
    if (start[0] == 0 && count[0] == 0 && stride[0] == 0 && imap[0] == 0 && op[0] == 0) {
        return 0;
    }

    // Call the function with the extracted parameters
    nc_put_varm_ulonglong(ncid, varid, start, count, stride, imap, op);

    return 0;
}