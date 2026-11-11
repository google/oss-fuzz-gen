#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_556(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int ncid = *(const int *)data;

    // Allocate memory for the output parameter
    int unlimdimid;
    
    // Call the function-under-test
    int result = nc_inq_unlimdim(ncid, &unlimdimid);

    // Use the result and unlimdimid to prevent compiler optimizations
    (void)result;
    (void)unlimdimid;

    return 0;
}