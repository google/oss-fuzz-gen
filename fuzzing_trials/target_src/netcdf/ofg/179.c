#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(char *)) {
        return 0;
    }

    // Extract integers from data
    int ncid = *((int *)data);
    data += sizeof(int);
    int varid = *((int *)data);
    data += sizeof(int);

    // Extract size_t from data
    size_t index = *((size_t *)data);
    data += sizeof(size_t);

    // Extract string from remaining data
    size_t str_size = size - sizeof(int) * 2 - sizeof(size_t);
    char *str = (char *)malloc(str_size + 1);
    if (str == NULL) return 0;
    memcpy(str, data, str_size);
    str[str_size] = '\0';

    // Prepare pointers for the function call
    const size_t *start = &index;
    const char *stringp = str;

    // Call the function-under-test
    nc_put_var1_string(ncid, varid, start, &stringp);

    // Clean up
    free(str);

    return 0;
}