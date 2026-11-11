#include <stdint.h>
#include <stddef.h>

// Function under test
int cmsGetEncodedCMMversion();

// Fuzzing harness
int LLVMFuzzerTestOneInput_485(const uint8_t *data, size_t size) {
    // Call the function under test
    int version = cmsGetEncodedCMMversion();

    // Use the returned version in some way to avoid compiler optimizations
    // that might remove the call to the function under test
    if (version == 0) {
        return 0;
    }

    return 0;
}