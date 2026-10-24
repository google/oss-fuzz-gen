#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int nc_put_vars_uint(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const unsigned int *value);

int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);
    const unsigned int *value = (const unsigned int *)(data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_uint(ncid, varid, start, count, stride, value);

    return 0;
}