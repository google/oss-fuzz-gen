#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_505(const uint8_t *data, size_t size) {
    // Ensure there's enough data for the parameters
    if (size < sizeof(size_t) + sizeof(int)) {
        return 0;
    }

    // Extract the first two integers from the data for the ncid and varid
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Use the next part of the data as the size_t index
    size_t index = (size_t)data[2];

    // Use the next part of the data as the int value
    int value = (int)data[3];

    // Call the function-under-test
    nc_put_var1_int(ncid, varid, &index, &value);

    return 0;
}