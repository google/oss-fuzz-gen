#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_322(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(unsigned long long)) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    const size_t *indexp = (const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    const unsigned long long *value = (const unsigned long long *)data;

    // Call the function-under-test
    nc_put_var1_ulonglong(ncid, varid, indexp, value);

    return 0;
}