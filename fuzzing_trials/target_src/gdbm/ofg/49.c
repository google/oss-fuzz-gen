#include <stdint.h>
#include <stddef.h>  // Include to define size_t

// Function-under-test
void lex_trace(int);

// Fuzzing harness
int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure that the size is at least as large as an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int trace_level = *(const int *)data;

    // Call the function-under-test
    lex_trace(trace_level);

    return 0;
}