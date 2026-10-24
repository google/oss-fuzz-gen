#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_219(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(long)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int*)data);
    int varid = *((int*)(data + sizeof(int)));
    size_t index = *((size_t*)(data + sizeof(int) * 2));
    long value = *((long*)(data + sizeof(int) * 2 + sizeof(size_t)));

    // Call the function-under-test
    nc_put_var1_long(ncid, varid, &index, &value);

    return 0;
}