#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is declared in some header file
int nc_get_att_int(int ncid, int varid, const char *name, int *ip);

int LLVMFuzzerTestOneInput_272(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0; // Not enough data to proceed
    }

    // Extract integers from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Use the rest of the data as a string
    size_t name_len = size - 4;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0'; // Ensure null-termination

    // Prepare an integer pointer
    int result_value;
    int *ip = &result_value;

    // Call the function-under-test
    nc_get_att_int(ncid, varid, name, ip);

    // Clean up
    free(name);

    return 0;
}