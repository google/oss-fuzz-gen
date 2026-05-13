#include <stdint.h>
#include <stddef.h>  // Include this header for size_t

// Function-under-test
void gram_trace(int level);

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Ensure there is data to process
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first 4 bytes of data as an integer
    int trace_level = *(const int *)data;

    // Call the function-under-test with the fuzzed trace level
    gram_trace(trace_level);

    return 0;
}