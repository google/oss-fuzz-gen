#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

// Assuming the function nc_rc_set is declared somewhere
int nc_rc_set(const char *key, const char *value);

int LLVMFuzzerTestOneInput_431(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least two null-terminated strings
    if (size < 2) {
        return 0;
    }

    // Find a midpoint to split the input data into two strings
    size_t midpoint = size / 2;

    // Allocate memory for the key and value strings
    char *key = (char *)malloc(midpoint + 1);
    char *value = (char *)malloc(size - midpoint + 1);

    if (key == NULL || value == NULL) {
        free(key);
        free(value);
        return 0;
    }

    // Copy data into key and value, ensuring null-termination
    memcpy(key, data, midpoint);
    key[midpoint] = '\0';
    memcpy(value, data + midpoint, size - midpoint);
    value[size - midpoint] = '\0';

    // Call the function-under-test
    nc_rc_set(key, value);

    // Free allocated memory
    free(key);
    free(value);

    return 0;
}