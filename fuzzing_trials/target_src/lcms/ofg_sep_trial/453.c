#include <stdint.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_453(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract the required parameters
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract cmsColorSpaceSignature from the input data
    cmsColorSpaceSignature colorSpaceSignature;
    memcpy(&colorSpaceSignature, data, sizeof(cmsColorSpaceSignature));

    // Extract cmsFloat64Number from the input data
    cmsFloat64Number inkLimit;
    memcpy(&inkLimit, data + sizeof(cmsColorSpaceSignature), sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateInkLimitingDeviceLink(colorSpaceSignature, inkLimit);

    // Clean up if a valid profile was created
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}