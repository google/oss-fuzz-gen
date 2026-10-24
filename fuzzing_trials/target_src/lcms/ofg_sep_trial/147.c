#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    cmsColorSpaceSignature colorSpaceSignature;

    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0; // Not enough data to form a valid cmsColorSpaceSignature
    }

    // Copy data into colorSpaceSignature, ensuring it is not NULL
    memcpy(&colorSpaceSignature, data, sizeof(cmsColorSpaceSignature));

    // Call the function-under-test
    cmsUInt32Number channels = cmsChannelsOf(colorSpaceSignature);

    // Use the result in some way to prevent it from being optimized away
    if (channels == 0) {
        return 0;
    }

    return 0;
}