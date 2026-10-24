#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is declared in some header file
int nc_rename_dim(int ncid, int dimid, const char *name);

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating valid parameters
    if (size < 3) {
        return 0;
    }

    // Initialize parameters for nc_rename_dim using input data
    int ncid = data[0];  // Use the first byte of data for ncid
    int dimid = data[1]; // Use the second byte of data for dimid

    // Create a null-terminated string from the remaining input data
    char *name = (char *)malloc(size - 2 + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, &data[2], size - 2);
    name[size - 2] = '\0';

    // Call the function under test
    nc_rename_dim(ncid, dimid, name);

    // Clean up
    free(name);

    return 0;
}