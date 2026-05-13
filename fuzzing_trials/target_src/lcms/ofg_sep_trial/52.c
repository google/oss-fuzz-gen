#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Function-under-test
cmsColorSpaceSignature _cmsICCcolorSpace(int input);

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure there's enough data to read an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first bytes of data as an integer
    int input = *((int*)data);

    // Call the function-under-test
    cmsColorSpaceSignature result = _cmsICCcolorSpace(input);

    // Use the result to avoid compiler optimizations that might skip the function call
    (void)result;

    return 0;
}