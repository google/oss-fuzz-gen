#include <stdint.h>
#include <stdio.h>

// Function-under-test
void yyerror(const char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and not empty
    if (size == 0) {
        return 0;
    }

    // Allocate a buffer with an extra byte for the null-terminator
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }

    // Copy the data into the buffer and null-terminate it
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    yyerror(input);

    // Free the allocated buffer
    free(input);

    return 0;
}