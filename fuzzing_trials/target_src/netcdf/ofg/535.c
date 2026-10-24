#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

extern int nc_put_var_long(int, int, const long *);

int LLVMFuzzerTestOneInput_535(const uint8_t *data, size_t size) {
    if (size < sizeof(long)) {
        return 0; // Not enough data to form a long
    }

    // Initialize parameters for nc_put_var_long
    int ncid = 0; // Example netCDF ID, should be a valid ID in a real scenario
    int varid = 0; // Example variable ID, should be a valid ID in a real scenario

    // Use the first sizeof(long) bytes of data as the long value
    long value;
    memcpy(&value, data, sizeof(long));

    // Call the function-under-test
    nc_put_var_long(ncid, varid, &value);

    return 0;
}