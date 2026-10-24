#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    cmsColorSpaceSignature colorSpaceSignature;

    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Copy the input data into the colorSpaceSignature variable
    memcpy(&colorSpaceSignature, data, sizeof(cmsColorSpaceSignature));

    // Call the function-under-test
    cmsUInt32Number channels = cmsChannelsOf(colorSpaceSignature);

    // Use the result in some way to avoid compiler optimizations
    volatile cmsUInt32Number result = channels;
    (void)result;

    return 0;
}