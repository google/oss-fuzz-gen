#include <stdint.h>
#include <stddef.h>  // Include this header to define 'size_t'

// Function-under-test
void input_context_drain();

// Fuzzing harness
int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Directly call the function-under-test
    input_context_drain();

    return 0;
}