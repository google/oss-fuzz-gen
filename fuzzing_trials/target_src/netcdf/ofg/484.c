#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_484(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract two integers from the data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));

    // Declare a variable of type nc_type
    nc_type vartype;

    // Call the function-under-test
    int result = nc_inq_vartype(ncid, varid, &vartype);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

    return 0;
}