#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_485(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract two integers and a nc_type
    if (size < sizeof(int) * 2 + sizeof(nc_type)) {
        return 0;
    }

    // Extract the first integer from the data
    int ncid = *((int *)data);
    data += sizeof(int);

    // Extract the second integer from the data
    int varid = *((int *)data);
    data += sizeof(int);

    // Create a nc_type variable and initialize it
    nc_type vartype = NC_NAT; // NC_NAT is a placeholder for "not a type"

    // Call the function-under-test
    int result = nc_inq_vartype(ncid, varid, &vartype);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != NC_NOERR) {
        // Handle error if needed
    }

    return 0;
}