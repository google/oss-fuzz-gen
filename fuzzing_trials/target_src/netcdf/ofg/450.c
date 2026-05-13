#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_450(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the parameters
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t)) {
        return 0;
    }

    // Extract the parameters from the input data
    int param1 = *(int *)data;
    nc_type param2 = *(nc_type *)(data + sizeof(int));
    size_t data_offset = sizeof(int) + sizeof(nc_type);
    size_t param4 = *(size_t *)(data + data_offset);

    // Ensure the data pointer is within bounds
    if (data_offset + sizeof(size_t) > size) {
        return 0;
    }

    // Create a non-NULL data pointer
    void *param3 = malloc(param4);
    if (param3 == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = nc_reclaim_data(param1, param2, param3, param4);

    // Free the allocated memory
    free(param3);

    return 0;
}