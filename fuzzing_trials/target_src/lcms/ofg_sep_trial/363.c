#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free

// Function-under-test
int cmsstrcasecmp(const char *s1, const char *s2);

// Fuzzing harness
int LLVMFuzzerTestOneInput_363(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create two strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two strings
    size_t mid = size / 2;

    // Allocate memory for the two strings, ensuring null-termination
    char *str1 = (char *)malloc(mid + 1);
    char *str2 = (char *)malloc(size - mid + 1);

    if (str1 == NULL || str2 == NULL) {
        // If memory allocation fails, exit
        free(str1);
        free(str2);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(str1, data, mid);
    str1[mid] = '\0';

    memcpy(str2, data + mid, size - mid);
    str2[size - mid] = '\0';

    // Call the function-under-test
    int result = cmsstrcasecmp(str1, str2);

    // Free allocated memory
    free(str1);
    free(str2);

    return 0;
}