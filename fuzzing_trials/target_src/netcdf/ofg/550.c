#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assume the function is defined in some library
int nc_put_var_text(int ncid, int varid, const char *text);

int LLVMFuzzerTestOneInput_550(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract ncid and varid
    if (size < 2) {
        return 0; // Not enough data to extract ncid and varid
    }

    // Derive ncid and varid from input data to ensure variability
    int ncid = data[0]; // Use the first byte of data for ncid
    int varid = data[1]; // Use the second byte of data for varid

    // Allocate memory for text and ensure it's null-terminated
    char *text = (char *)malloc(size - 2 + 1); // Adjust size for text
    if (text == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy data to text and null-terminate it
    memcpy(text, data + 2, size - 2); // Adjust offset for text
    text[size - 2] = '\0';

    // Call the function-under-test
    nc_put_var_text(ncid, varid, text);

    // Free the allocated memory
    free(text);

    return 0;
}