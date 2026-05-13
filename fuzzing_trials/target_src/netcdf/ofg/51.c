#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(int) * 2 + sizeof(long long)) {
        return 0;
    }

    // Extract the first integer from the input data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer from the input data
    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the long long value from the input data
    const long long *value = (const long long *)data;

    // Call the function-under-test
    nc_put_var_longlong(ncid, varid, value);

    return 0;
}