#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int cmsstrcasecmp(const char *s1, const char *s2);

// Fuzzing harness for cmsstrcasecmp
int LLVMFuzzerTestOneInput_362(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two strings
    size_t mid = size / 2;

    // Allocate memory for the two strings, ensuring null-termination
    char *s1 = (char *)malloc(mid + 1);
    char *s2 = (char *)malloc(size - mid + 1);

    if (s1 == NULL || s2 == NULL) {
        free(s1);
        free(s2);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(s1, data, mid);
    s1[mid] = '\0';

    memcpy(s2, data + mid, size - mid);
    s2[size - mid] = '\0';

    // Call the function-under-test
    int result = cmsstrcasecmp(s1, s2);

    // Free the allocated memory
    free(s1);
    free(s2);

    return 0;
}