#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    int fletcher32;
    
    // Call the function-under-test
    int result = nc_inq_var_fletcher32(ncid, varid, &fletcher32);

    // Optionally, you can check the result or use fletcher32 for further processing

    return 0;
}