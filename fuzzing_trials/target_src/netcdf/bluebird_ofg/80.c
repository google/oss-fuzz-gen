#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract meaningful values
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract an integer for ncid
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract an integer for dimid
    int dimid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for the name and ensure it's null-terminated
    char name[256];
    memset(name, 0, sizeof(name));
    size_t name_length = size < sizeof(name) - 1 ? size : sizeof(name) - 1;
    memcpy(name, data, name_length);

    // Allocate memory for the length
    size_t length;
    
    // Call the function-under-test
    nc_inq_dim(ncid, dimid, name, &length);

    return 0;
}