#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_370(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract required parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *(int *)(data);
    int param2 = *(int *)(data + sizeof(int));
    nc_type param4 = *(nc_type *)(data + sizeof(int) * 2);
    size_t param5 = *(size_t *)(data + sizeof(int) * 2 + sizeof(nc_type));

    // Ensure there is enough data for the string and float array
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1 + param5 * sizeof(float)) {
        return 0;
    }

    // Extract string parameter
    const char *param3 = (const char *)(data + sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t));

    // Extract float array parameter
    const float *param6 = (const float *)(data + sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + strlen(param3) + 1);

    // Call the function-under-test
    nc_put_att_float(param1, param2, param3, param4, param5, param6);

    return 0;
}