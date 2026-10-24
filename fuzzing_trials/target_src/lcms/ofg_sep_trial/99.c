#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    cmsColorSpaceSignature colorSpaceSignature = *(const cmsColorSpaceSignature*)data;

    // Call the function-under-test
    cmsInt32Number channels = cmsChannelsOfColorSpace(colorSpaceSignature);

    // Use the result in some way to avoid compiler optimizations
    if (channels < 0) {
        // Handle invalid channel count scenario
    }

    return 0;
}