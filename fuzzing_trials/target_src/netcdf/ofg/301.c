#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_301(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) + sizeof(double)) {
        return 0;
    }

    // Extract values from the input data
    int ncid = (int)data[0];  // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid

    // Use the next bytes for size_t index
    size_t index;
    memcpy(&index, data + 2, sizeof(size_t));

    // Use the remaining bytes for the double value
    double value;
    memcpy(&value, data + 2 + sizeof(size_t), sizeof(double));

    // Call the function-under-test
    nc_put_var1_double(ncid, varid, &index, &value);

    return 0;
}