#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assume the function is declared in a header file we can include
#include "netcdf.h"  // Hypothetical header for the function nc_get_att

int LLVMFuzzerTestOneInput_537(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract a meaningful test case
    if (size < 4) {
        return 0;
    }

    // Extract the first two integers from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Use the rest of the data as a string for the attribute name
    const char *name = (const char *)&data[2];

    // Prepare a buffer to store the attribute value
    char value[256];  // Assuming the attribute value is a string with a reasonable length

    // Ensure the name is null-terminated
    size_t name_len = size - 2;
    if (name_len >= 255) {
        name_len = 255;
    }
    char name_buffer[256];
    strncpy(name_buffer, name, name_len);
    name_buffer[name_len] = '\0';

    // Call the function-under-test
    nc_get_att(ncid, varid, name_buffer, (void *)value);

    return 0;
}