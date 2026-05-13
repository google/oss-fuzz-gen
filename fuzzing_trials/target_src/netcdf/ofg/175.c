#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(long)) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *(const int *)data;
    int param2 = *(const int *)(data + sizeof(int));

    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));

    const long *value = (const long *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    nc_put_vara_long(param1, param2, start, count, value);

    return 0;
}