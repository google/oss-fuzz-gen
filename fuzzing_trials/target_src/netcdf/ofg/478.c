#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/netcdf-c/include/netcdf.h"

int nc_copy_data_all(int, nc_type, const void *, size_t, void **);

int LLVMFuzzerTestOneInput_478(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t)) {
        return 0;
    }

    int int_param;
    nc_type nc_type_param;
    size_t size_param;
    void *output = NULL;

    // Extract int_param from data
    memcpy(&int_param, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    // Extract nc_type_param from data
    memcpy(&nc_type_param, data, sizeof(nc_type));
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Extract size_param from data
    memcpy(&size_param, data, sizeof(size_t));
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Ensure size_param does not exceed remaining data size
    if (size_param > size) {
        size_param = size;
    }

    // Call the function-under-test
    nc_copy_data_all(int_param, nc_type_param, data, size_param, &output);

    // Free the allocated output if any
    if (output != NULL) {
        free(output);
    }

    return 0;
}