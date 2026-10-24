#include <stdint.h>
#include <stddef.h> // Include this header for size_t

extern void lex_trace(int);

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to form an int
    }

    // Extract an integer from the input data
    int trace_level = *(int *)data;

    // Call the function-under-test with the extracted integer
    lex_trace(trace_level);

    return 0;
}