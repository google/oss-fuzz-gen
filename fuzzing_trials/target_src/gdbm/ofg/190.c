#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function prototype
int gdbm_latest_snapshot(const char *, const char *, const char **);

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create meaningful strings
    if (size < 2) return 0;

    // Allocate memory for the first string and ensure null-termination
    char *str1 = (char *)malloc(size / 2 + 1);
    if (!str1) return 0;
    memcpy(str1, data, size / 2);
    str1[size / 2] = '\0';

    // Allocate memory for the second string and ensure null-termination
    char *str2 = (char *)malloc(size / 2 + 1);
    if (!str2) {
        free(str1);
        return 0;
    }
    memcpy(str2, data + size / 2, size / 2);
    str2[size / 2] = '\0';

    // Pointer to store the result
    const char *result = NULL;

    // Call the function-under-test
    gdbm_latest_snapshot(str1, str2, &result);

    // Free allocated memory
    free(str1);
    free(str2);

    return 0;
}