#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_498(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t)) {
        return 0;
    }

    // Extract the first integer from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer from the data
    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the start array
    size_t start[1];
    start[0] = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Extract the count array
    size_t count[1];
    count[0] = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Extract the stride array
    ptrdiff_t stride[1];
    stride[0] = *(const ptrdiff_t *)data;
    data += sizeof(ptrdiff_t);
    size -= sizeof(ptrdiff_t);

    // Prepare the string array
    const char *string_data[1];
    if (size > 0) {
        string_data[0] = (const char *)data;
    } else {
        const char *default_string = "default";
        string_data[0] = default_string;
    }

    // Call the function-under-test
    nc_put_vars_string(ncid, varid, start, count, stride, string_data);

    return 0;
}