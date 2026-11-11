#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_vars_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned long long *value);

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 3 + sizeof(ptrdiff_t) * 3 + sizeof(unsigned long long)) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Ensure the rest of the data is correctly aligned for size_t and ptrdiff_t
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t) * 3);
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 6);

    // To ensure the parameters are not null and have meaningful values, we can set some defaults
    size_t start_default[3] = {0, 0, 0};
    size_t count_default[3] = {1, 1, 1};
    ptrdiff_t stride_default[3] = {1, 1, 1};

    // Use memcpy to safely copy data into our default arrays
    memcpy(start_default, start, sizeof(size_t) * 3);
    memcpy(count_default, count, sizeof(size_t) * 3);
    memcpy(stride_default, stride, sizeof(ptrdiff_t) * 3);

    unsigned long long value = 0;

    // Call the function-under-test with defaulted parameters
    nc_get_vars_ulonglong(ncid, varid, start_default, count_default, stride_default, &value);

    return 0;
}