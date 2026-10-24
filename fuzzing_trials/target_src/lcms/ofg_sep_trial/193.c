#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_193(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract a cmsColorSpaceSignature
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Interpret the input data as a cmsColorSpaceSignature
    cmsColorSpaceSignature colorSpaceSignature = *(const cmsColorSpaceSignature *)data;

    // Call the function-under-test
    int result = _cmsLCMScolorSpace(colorSpaceSignature);

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result;

    return 0;
}