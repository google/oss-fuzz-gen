#include <stddef.h>
#include <stdint.h>

// Function declaration for the function-under-test
void input_context_drain();

// Fuzzing harness
int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Call the function-under-test
    input_context_drain();

    return 0;
}