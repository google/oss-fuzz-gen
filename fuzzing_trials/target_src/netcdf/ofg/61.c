#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(unsigned char)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));
    const unsigned char *values = (const unsigned char *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    nc_put_vara_uchar(ncid, varid, start, count, values);

    return 0;
}