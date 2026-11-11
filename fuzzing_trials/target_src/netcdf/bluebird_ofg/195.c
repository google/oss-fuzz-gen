#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// Assume the function is declared in a header file we have access to.
int nc_put_var_ubyte(int ncid, int varid, const unsigned char *op);

int LLVMFuzzerTestOneInput_195(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract meaningful inputs
    if (size < 2) {
        return 0;
    }

    // Use first byte for ncid, second byte for varid
    int ncid = data[0];
    int varid = data[1];

    // Remaining data is used for the unsigned char array
    const unsigned char *op = data + 2;
    size_t op_size = size - 2;

    // Ensure op is not NULL by checking op_size
    if (op_size > 0) {
        // Call the function-under-test
        nc_put_var_ubyte(ncid, varid, op);
    }

    return 0;
}