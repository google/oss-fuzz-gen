#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_499(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract multiple parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    size_t start[1];
    start[0] = *(size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    size_t count[1];
    count[0] = *(size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    ptrdiff_t stride[1];
    stride[0] = *(ptrdiff_t *)data;
    data += sizeof(ptrdiff_t);
    size -= sizeof(ptrdiff_t);

    // Ensure there is at least one remaining byte for the string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the string array
    const char *str_array[1];
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0;
    }

    // Copy the remaining data into the string and null-terminate it
    memcpy(str, data, size);
    str[size] = '\0';
    str_array[0] = str;

    // Call the function-under-test
    nc_put_vars_string(ncid, varid, start, count, stride, str_array);

    // Free the allocated memory
    free(str);

    return 0;
}