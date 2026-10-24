#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int nc_put_vars_longlong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const long long *op);

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(long long)) {
        return 0;
    }

    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    const size_t *start = (const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    const size_t *count = (const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    const ptrdiff_t *stride = (const ptrdiff_t *)data;
    data += sizeof(ptrdiff_t);
    size -= sizeof(ptrdiff_t);

    const long long *op = (const long long *)data;

    // Call the function-under-test
    nc_put_vars_longlong(ncid, varid, start, count, stride, op);

    return 0;
}