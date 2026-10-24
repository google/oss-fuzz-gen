#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract meaningful input
    if (size < 4) {
        return 0;
    }

    // Extract the first 4 bytes as an integer for ncid
    int ncid = *(const int *)data;

    // Calculate the remaining size for the name string
    size_t name_size = size - 4;

    // Allocate memory for the name string and ensure it's null-terminated
    char *name = (char *)malloc(name_size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 4, name_size);
    name[name_size] = '\0';

    // Prepare an integer pointer for the varid output
    int varid;

    // Call the function-under-test
    nc_inq_varid(ncid, name, &varid);

    // Clean up allocated memory
    free(name);

    return 0;
}