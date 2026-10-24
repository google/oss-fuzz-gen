#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Function-under-test
int variable_unset(const char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and non-empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the null-terminated string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }

    // Copy the data and null-terminate
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    variable_unset(input);

    // Free the allocated memory
    free(input);

    return 0;
}