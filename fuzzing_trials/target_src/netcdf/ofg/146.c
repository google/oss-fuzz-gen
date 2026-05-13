#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extracting two integers from data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));

    // Allocate memory for the output parameter
    int ndims;
    
    // Call the function-under-test
    int result = nc_inq_varndims(ncid, varid, &ndims);

    // Optionally, you can check the result or use ndims in some way
    // For fuzzing, we are mainly interested in calling the function

    return 0;
}