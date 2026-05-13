#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the implementation of parse_content_length
#include "/src/kamailio/src/core/parser/parse_content.c"

// Function signature to be fuzzed
// Remove the conflicting declaration since the function is included from the implementation file
// char *parse_content_length(const char *str1, const char *str2, const int *num);

// Define the main function for fuzzing
int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to split into two strings and an int
    if (size < sizeof(int) + 2) {
        return 0;
    }

    // Split the data into two strings and an integer
    size_t str1_len = size / 2;
    size_t str2_len = size - str1_len - sizeof(int);

    // Allocate memory for the strings and integer
    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);
    int *num = (int *)malloc(sizeof(int));

    if (str1 == NULL || str2 == NULL || num == NULL) {
        free(str1);
        free(str2);
        free(num);
        return 0;
    }

    // Copy data into the allocated memory
    memcpy(str1, data, str1_len);
    str1[str1_len] = '\0';  // Null-terminate the string

    memcpy(str2, data + str1_len, str2_len);
    str2[str2_len] = '\0';  // Null-terminate the string

    memcpy(num, data + str1_len + str2_len, sizeof(int));

    // Call the function under test
    char *result = parse_content_length(str1, str2, num);

    // Free the allocated memory
    free(str1);
    free(str2);
    free(num);

    // Free the result if it was allocated by the function under test
    free(result);

    return 0;
}