#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract necessary parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    const char *name = (const char *)(data + sizeof(int) * 2);
    size_t name_len = size - sizeof(int) * 2;

    // Ensure the name is null-terminated
    char *name_copy = (char *)malloc(name_len + 1);
    if (name_copy == NULL) {
        return 0;
    }
    memcpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';

    // Prepare the output parameter
    size_t attlen;

    // Call the function-under-test
    nc_inq_attlen(ncid, varid, name_copy, &attlen);

    // Clean up
    free(name_copy);

    return 0;
}