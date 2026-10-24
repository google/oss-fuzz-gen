#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid; // NetCDF file ID
    nc_type xtype; // Variable to hold the netCDF type
    char name[NC_MAX_NAME + 1]; // Buffer to hold the type name
    size_t sizep;

    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(int) + sizeof(nc_type)) {
        return 0; // Not enough data to proceed
    }

    // Extract ncid and xtype from the input data
    memcpy(&ncid, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    memcpy(&xtype, data, sizeof(nc_type));
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Ensure size is within bounds to avoid buffer overflow
    if (size > NC_MAX_NAME) {
        size = NC_MAX_NAME;
    }

    // Copy data into the name buffer, ensuring null termination
    if (size > 0) {
        memcpy(name, data, size);
        name[size] = '\0';
    } else {
        name[0] = '\0';
    }

    // Call the function-under-test
    int result = nc_inq_type(ncid, xtype, name, &sizep);

    // Return the result to help guide the fuzzer
    return result;
}