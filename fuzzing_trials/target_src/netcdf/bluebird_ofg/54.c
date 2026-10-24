#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + sizeof(long long)) {
        return 0;
    }

    // Extract parameters from the data
    int param1 = *(int *)data;
    int param2 = *(int *)(data + sizeof(int));
    const char *param3 = "attribute_name"; // Use a fixed non-null string for attribute name
    nc_type param4 = *(nc_type *)(data + sizeof(int) * 2);
    size_t param5 = *(size_t *)(data + sizeof(int) * 2 + sizeof(nc_type));
    
    // Ensure param5 is non-zero to avoid passing a NULL pointer for param6
    if (param5 == 0) {
        param5 = 1;
    }

    // Allocate memory for param6
    const long long *param6 = (const long long *)(data + sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t));
    
    // Call the function-under-test
    nc_put_att_longlong(param1, param2, param3, param4, param5, param6);

    return 0;
}