#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assume the function-under-test is declared in some header
// #include "variable.h"

int variable_get(const char *, int, void **);

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating meaningful input
    if (size < 1) return 0;

    // Create a non-NULL string for the first parameter
    char key[256];
    size_t key_len = size < 255 ? size : 255;
    memcpy(key, data, key_len);
    key[key_len] = '\0';

    // Use the first byte of data to create an integer for the second parameter
    int index = (int)data[0];

    // Create a non-NULL pointer for the third parameter
    void *output = malloc(256); // Allocate some memory for the output

    // Call the function-under-test
    variable_get(key, index, &output);

    // Free allocated memory
    free(output);

    return 0;
}