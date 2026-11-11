#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
char *tildexpand(char *);

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated and non-empty
    if (size == 0) return 0;

    // Allocate memory for the input string and copy the data
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    char *result = tildexpand(input);

    // Free the allocated memory and the result if necessary
    free(input);
    if (result != input) {
        free(result);
    }

    return 0;
}