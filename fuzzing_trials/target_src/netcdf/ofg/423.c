#include <stdint.h>
#include <stddef.h>

// Assume the function nc_initialize is defined elsewhere and included properly
int nc_initialize();

int LLVMFuzzerTestOneInput_423(const uint8_t *data, size_t size) {
    // Call the function-under-test
    int result = nc_initialize();

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result; // This is a no-op to use the result variable

    return 0;
}