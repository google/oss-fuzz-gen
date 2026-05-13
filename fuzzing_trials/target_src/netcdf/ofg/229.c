#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_229(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < sizeof(size_t) + sizeof(float) + 2) {
        return 0;
    }

    // Extract values from the input data
    int ncid = (int)data[0]; // Assuming the first byte for ncid
    int varid = (int)data[1]; // Assuming the second byte for varid

    // Extract a size_t value from the input data
    size_t index;
    memcpy(&index, data + 2, sizeof(size_t));

    // Extract a float value from the input data
    float value;
    memcpy(&value, data + 2 + sizeof(size_t), sizeof(float));

    // Call the function-under-test
    nc_put_var1_float(ncid, varid, &index, &value);

    return 0;
}