#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vars_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, unsigned long long *value);

int LLVMFuzzerTestOneInput_371(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < sizeof(size_t) * 6 + sizeof(ptrdiff_t) * 3 + sizeof(unsigned long long)) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t) * 3);
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 6);

    unsigned long long value;
    
    // Call the function-under-test
    nc_get_vars_ulonglong(ncid, varid, start, count, stride, &value);

    return 0;
}