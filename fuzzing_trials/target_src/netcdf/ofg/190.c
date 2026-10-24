#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    // Check if size is sufficient to extract required parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    int dimid = *(const int *)(data + sizeof(int));
    char name[NC_MAX_NAME + 1];
    size_t len;

    // Ensure name is null-terminated
    size_t name_len = size - sizeof(int) * 2;
    if (name_len > NC_MAX_NAME) {
        name_len = NC_MAX_NAME;
    }
    memcpy(name, data + sizeof(int) * 2, name_len);
    name[name_len] = '\0';

    // Call the function-under-test
    nc_inq_dim(ncid, dimid, name, &len);

    return 0;
}