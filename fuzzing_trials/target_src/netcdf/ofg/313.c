#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
char *nc_rc_get(const char *filename);

int LLVMFuzzerTestOneInput_313(const uint8_t *data, size_t size) {
    // Ensure the data is not empty to be used as a filename
    if (size == 0) {
        return 0;
    }

    // Ensure the data is null-terminated to be used as a filename
    char *filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Basic transformation to ensure the filename is valid
    // Replace any '/' or '\0' in the middle of the filename with '_'
    for (size_t i = 0; i < size; ++i) {
        if (filename[i] == '/' || filename[i] == '\0') {
            filename[i] = '_';
        }
    }

    // Call the function-under-test
    char *result = nc_rc_get(filename);

    // Free the allocated memory for the filename
    free(filename);

    // Free the result if it is not NULL
    if (result != NULL) {
        free(result);
    }

    return 0;
}