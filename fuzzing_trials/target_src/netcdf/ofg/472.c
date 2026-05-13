#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_472(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract required parameters
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)(data);
    int varid = *(int *)(data + sizeof(int));

    // Allocate memory for the dimids array
    // Assuming a reasonable maximum number of dimensions, e.g., 10
    int dimids[10];

    // Call the function-under-test
    int result = nc_inq_vardimid(ncid, varid, dimids);

    // Use the result to avoid unused variable warning
    (void)result;

    return 0;
}