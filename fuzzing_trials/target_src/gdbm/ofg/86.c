#include <stdint.h>
#include <stddef.h>

// Function-under-test
void yyerror(const char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) return 0; // Handle memory allocation failure

    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    yyerror(null_terminated_data);

    // Clean up
    free(null_terminated_data);
    return 0;
}