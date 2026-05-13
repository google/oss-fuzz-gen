#include <stdint.h>
#include <stddef.h>

// Function-under-test
void gram_trace(int trace_level);

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Ensure we have enough data to read an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first few bytes of data as an integer
    int trace_level = *(const int *)data;

    // Call the function-under-test
    gram_trace(trace_level);

    return 0;
}