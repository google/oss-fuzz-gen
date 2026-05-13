#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int nc_get_att_uchar(int ncid, int varid, const char *name, unsigned char *value);

int LLVMFuzzerTestOneInput_452(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 3) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = data[0];  // Use the first byte as ncid
    int varid = data[1]; // Use the second byte as varid

    // Ensure there is enough data for a null-terminated string
    size_t name_len = size - 2;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Allocate memory for the output value
    unsigned char value;
    
    // Call the function-under-test
    nc_get_att_uchar(ncid, varid, name, &value);

    // Clean up
    free(name);

    return 0;
}