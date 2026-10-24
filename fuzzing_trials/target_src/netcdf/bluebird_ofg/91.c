#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Assuming the function is declared in a header file
int nc_get_att_uchar(int ncid, int varid, const char *name, unsigned char *value);

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract meaningful values
    if (size < 4) { // Adjusted to ensure there's at least one byte for the name
        return 0;
    }

    // Extract integers from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Use the remaining data as the name string
    const char *name = (const char *)(data + 2);

    // Ensure the name is null-terminated and has at least one character
    char name_buffer[256];
    size_t name_length = size - 2; // Calculate the length of the name
    if (name_length > sizeof(name_buffer) - 1) {
        name_length = sizeof(name_buffer) - 1;
    }
    strncpy(name_buffer, name, name_length);
    name_buffer[name_length] = '\0';

    // Prepare a buffer for the unsigned char output
    unsigned char value;

    // Call the function-under-test
    nc_get_att_uchar(ncid, varid, name_buffer, &value);

    return 0;
}