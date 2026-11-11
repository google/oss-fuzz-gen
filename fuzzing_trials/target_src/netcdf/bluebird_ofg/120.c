#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the data
    int ncid = *(const int *)data;

    // Allocate memory for the format variable
    int format;
    
    // Call the function-under-test
    nc_inq_format(ncid, &format);

    return 0;
}