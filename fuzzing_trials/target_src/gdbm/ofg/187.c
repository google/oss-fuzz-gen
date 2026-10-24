#include <stddef.h>  // Include this for size_t
#include <stdint.h>  // Include this for uint8_t

// Declaration of the function-under-test
void print_prompt_at_bol();

// Fuzzer entry point
int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    // Call the function-under-test
    print_prompt_at_bol();

    return 0;
}