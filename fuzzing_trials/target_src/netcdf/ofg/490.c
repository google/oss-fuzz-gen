#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_490(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) + sizeof(signed char) + 2) {
        return 0; // Not enough data to proceed
    }

    // Extract the integer file ID and variable ID from the data
    int ncid = (int)data[0]; // Assuming the first byte is the file ID
    int varid = (int)data[1]; // Assuming the second byte is the variable ID

    // Extract the size_t index from the data
    size_t index;
    memcpy(&index, data + 2, sizeof(size_t));

    // Extract the signed char value from the data
    signed char value;
    memcpy(&value, data + 2 + sizeof(size_t), sizeof(signed char));

    // Call the function-under-test
    nc_put_var1_schar(ncid, varid, &index, &value);

    return 0;
}