#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract a cmsColorSpaceSignature
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Extract a cmsColorSpaceSignature from the input data
    cmsColorSpaceSignature colorSpaceSignature;
    memcpy(&colorSpaceSignature, data, sizeof(cmsColorSpaceSignature));

    // Call the function-under-test
    cmsInt32Number channels = cmsChannelsOfColorSpace(colorSpaceSignature);

    // Use the result in some way (e.g., print, log, etc.)
    // For fuzzing, we generally don't need to do anything with the result
    (void)channels; // Suppress unused variable warning

    return 0;
}