#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assume the function nc_get_att_long is defined in an external library
// and the necessary header is included.
extern int nc_get_att_long(int ncid, int varid, const char *name, long *value);

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for nc_get_att_long
    int ncid = 1;  // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure the size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the name string and ensure it's null-terminated
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    long value = 0; // Initialize the long pointer

    // Call the function-under-test
    nc_get_att_long(ncid, varid, name, &value);

    // Clean up
    free(name);

    return 0;
}