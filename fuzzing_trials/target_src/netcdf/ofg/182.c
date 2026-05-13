#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_182(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    const size_t *indexp = (const size_t *)(data + sizeof(int) * 2);
    const unsigned int *valuep = (const unsigned int *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_uint(ncid, varid, indexp, valuep);

    return 0;
}