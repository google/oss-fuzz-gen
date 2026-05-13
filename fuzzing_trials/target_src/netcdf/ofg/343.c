#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_343(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < sizeof(size_t) + 2) {
        return 0;
    }

    // Extract values from the input data
    int ncid = (int)data[0]; // Assuming the first byte is used for ncid
    int varid = (int)data[1]; // Assuming the second byte is used for varid

    // Use the next bytes for the size_t index
    size_t index;
    memcpy(&index, data + 2, sizeof(size_t));

    // Ensure there's at least one character for the text
    const char *text = (const char *)(data + 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_text(ncid, varid, &index, text);

    return 0;
}