#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
int nc_free_string(size_t count, char **strings);

int LLVMFuzzerTestOneInput_243(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0; // Not enough data to determine the count
    }

    // Extract the count from the data
    size_t count = *((size_t *)data);
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Ensure count does not exceed a reasonable limit to prevent excessive memory allocation
    // and ensure there is enough data to initialize at least one string.
    if (count > size / 10 || count == 0) {
        return 0;
    }

    // Allocate memory for the array of strings
    char **strings = (char **)malloc(count * sizeof(char *));
    if (strings == NULL) {
        return 0; // Memory allocation failed
    }

    // Initialize each string
    for (size_t i = 0; i < count; i++) {
        if (size == 0) {
            strings[i] = strdup(""); // Ensure non-null strings
        } else {
            // Allocate memory for each string and copy data
            size_t len = size < 10 ? size : 10; // Limit string length to 10 for safety
            strings[i] = (char *)malloc(len + 1);
            if (strings[i] != NULL) {
                memcpy(strings[i], data, len);
                strings[i][len] = '\0';
                data += len;
                size -= len;
            } else {
                strings[i] = strdup(""); // Fallback to empty string if allocation fails
            }
        }
    }

    // Call the function-under-test
    nc_free_string(count, strings);

    // Free allocated memory
    for (size_t i = 0; i < count; i++) {
        free(strings[i]);
    }
    free(strings);

    return 0;
}