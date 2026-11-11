#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_551(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract parameters
    if (size < 2) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = (int)data[0];  // Using first byte for ncid
    int varid = (int)data[1]; // Using second byte for varid

    // Allocate memory for the text variable
    char *text = (char *)malloc(size - 2 + 1); // +1 for null terminator
    if (text == NULL) {
        return 0;
    }

    // Copy the remaining data into text and null-terminate it
    memcpy(text, data + 2, size - 2);
    text[size - 2] = '\0';

    // Call the function-under-test
    nc_put_var_text(ncid, varid, text);

    // Free allocated memory
    free(text);

    return 0;
}