#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Function-under-test declaration
int variable_is_true(const char *);

// LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for a string input
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    variable_is_true(input);

    // Free allocated memory
    free(input);

    return 0;
}