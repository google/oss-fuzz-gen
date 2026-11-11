#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assuming the function is declared in an external library
extern int nc_get_att_ulonglong(int ncid, int varid, const char *name, unsigned long long *value);

int LLVMFuzzerTestOneInput_437(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract parameters
    if (size < 2 + sizeof(unsigned long long)) {
        return 0;
    }

    // Extracting parameters from the input data
    int ncid = (int)data[0];   // Use the first byte for ncid
    int varid = (int)data[1];  // Use the second byte for varid

    // Use the rest of the data as the name, ensuring it's null-terminated
    const char *name = (const char *)(data + 2);
    size_t name_length = size - 2;
    char name_buffer[256];

    if (name_length > sizeof(name_buffer) - 1) {
        name_length = sizeof(name_buffer) - 1;
    }

    memcpy(name_buffer, name, name_length);
    name_buffer[name_length] = '\0';

    unsigned long long value = 0;

    // Call the function with extracted parameters
    nc_get_att_ulonglong(ncid, varid, name_buffer, &value);

    return 0;
}