#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *((int *)data);
    int param2 = *((int *)(data + sizeof(int)));
    const char *param3 = (const char *)(data + sizeof(int) * 2);
    nc_type param4 = *((nc_type *)(data + sizeof(int) * 2 + 1));
    size_t param5 = *((size_t *)(data + sizeof(int) * 2 + 1 + sizeof(nc_type)));
    const signed char *param6 = (const signed char *)(data + sizeof(int) * 2 + 1 + sizeof(nc_type) + sizeof(size_t));

    // Call the function-under-test
    nc_put_att_schar(param1, param2, param3, param4, param5, param6);

    return 0;
}