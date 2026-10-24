#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Function-under-test declaration
char *make_prompt();

// Fuzzing harness
int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    // Call the function-under-test
    char *prompt = make_prompt();

    // Check if the result is not NULL and free the allocated memory
    if (prompt != NULL) {
        free(prompt);
    }

    return 0;
}