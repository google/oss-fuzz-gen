#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <string.h>

int LLVMFuzzerTestOneInput_231(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < sizeof(int) * 2 + sizeof(nc_type) + 1 + sizeof(size_t) + sizeof(short)) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));
    const char *param3 = (const char *)(data + 2 * sizeof(int));
    nc_type param4 = *((nc_type *)(data + 2 * sizeof(int) + strlen(param3) + 1));
    size_t param5 = *((size_t *)(data + 2 * sizeof(int) + strlen(param3) + 1 + sizeof(nc_type)));
    const short *param6 = (const short *)(data + 2 * sizeof(int) + strlen(param3) + 1 + sizeof(nc_type) + sizeof(size_t));

    // Call the function-under-test
    nc_put_att_short(param1, param2, param3, param4, param5, param6);

    return 0;
}