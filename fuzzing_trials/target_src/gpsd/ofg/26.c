#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Function-under-test
ssize_t hex_escapes(char *dest, const char *src);

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for both destination and source strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for destination and source strings
    char *dest = (char *)malloc(size);
    char *src = (char *)malloc(size);

    // Ensure memory allocation was successful
    if (dest == NULL || src == NULL) {
        free(dest);
        free(src);
        return 0;
    }

    // Copy data into source string and ensure null-termination
    memcpy(src, data, size - 1);
    src[size - 1] = '\0';

    // Call the function-under-test
    hex_escapes(dest, src);

    // Free allocated memory
    free(dest);
    free(src);

    return 0;
}