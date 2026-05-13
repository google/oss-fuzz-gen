#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Function-under-test
int variable_is_set(const char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and not empty
    if (size == 0) return 0;

    // Allocate memory for the input string and null-terminate it
    char *inputString = (char *)malloc(size + 1);
    if (!inputString) return 0;
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Call the function-under-test
    variable_is_set(inputString);

    // Clean up
    free(inputString);

    return 0;
}