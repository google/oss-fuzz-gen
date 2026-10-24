#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assume the function is declared in a header file we include
// #include "netcdf.h"

extern int nc_get_att_ubyte(int ncid, int varid, const char *name, unsigned char *value);

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < 4) {
        return 0;
    }

    // Extracting integer values for ncid and varid from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract a string for the name (ensure null-termination)
    char name[256];
    size_t name_len = size - 2 < 255 ? size - 2 : 255;
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0';

    // Prepare a buffer for the unsigned char value
    unsigned char value[256]; // Assuming a buffer size for demonstration

    // Call the function-under-test
    nc_get_att_ubyte(ncid, varid, name, value);

    return 0;
}