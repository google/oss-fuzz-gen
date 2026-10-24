#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(int)) {
        return 0;
    }

    // Extract file ID and variable ID from the data
    int file_id = (int)data[0];
    int var_id = (int)data[1];

    // Extract start, count, stride, and value from the data
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2);
    const int *value = (const int *)(data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_int(file_id, var_id, start, count, stride, value);

    return 0;
}