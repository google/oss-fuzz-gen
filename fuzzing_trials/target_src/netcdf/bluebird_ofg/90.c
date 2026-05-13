#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is defined in a library we are linking against.
extern int nc_get_att_int(int ncid, int varid, const char *name, int *ip);

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract meaningful data
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extracting parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Calculate the maximum length for the name string
    size_t max_name_length = size - sizeof(int) * 2;

    // Ensure the string is null-terminated and within bounds
    char name_buffer[256];
    size_t copy_length = max_name_length < sizeof(name_buffer) - 1 ? max_name_length : sizeof(name_buffer) - 1;
    strncpy(name_buffer, (const char *)(data + sizeof(int) * 2), copy_length);
    name_buffer[copy_length] = '\0';

    // Allocate memory for the output parameter
    int ip;
    
    // Call the function-under-test
    nc_get_att_int(ncid, varid, name_buffer, &ip);

    return 0;
}