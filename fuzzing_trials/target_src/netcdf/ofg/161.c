#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern int nc_get_att_ubyte(int ncid, int varid, const char *name, unsigned char *value);

int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to extract necessary parameters
    if (size < 3) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0]; // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid

    // Use the rest of the data for the name
    size_t name_len = size - 2;
    char name[name_len + 1];
    memcpy(name, &data[2], name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Prepare a buffer for the output value
    unsigned char value;

    // Call the function-under-test
    nc_get_att_ubyte(ncid, varid, name, &value);

    return 0;
}