#include <inttypes.h>
#include <stddef.h>

// Assume the function is defined in some header or source file
int ksr_hname_init_index();

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Since ksr_hname_init_index() does not take any parameters,
    // we can directly call it without needing to use 'data' or 'size'.
    int result = ksr_hname_init_index();

    // Optionally, you can use the result for further operations or checks
    // if needed for debugging or validation purposes.

    return 0; // Return 0 to indicate the fuzzer should continue
}