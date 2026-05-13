#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Function-under-test declaration
int variable_is_true(const char *);

// LLVMFuzzerTestOneInput function definition
int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) return 0; // Handle memory allocation failure
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Call the function-under-test
    int result = variable_is_true(input_str);

    // Free allocated memory
    free(input_str);

    return 0;
}