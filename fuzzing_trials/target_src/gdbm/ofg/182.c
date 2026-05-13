#include <stdint.h>
#include <stddef.h>  // Include this header for size_t

// Assume the function end_def is defined in an external library
extern void end_def();

int LLVMFuzzerTestOneInput_182(const uint8_t *data, size_t size) {
    // Call the function-under-test
    end_def();
    
    return 0;
}