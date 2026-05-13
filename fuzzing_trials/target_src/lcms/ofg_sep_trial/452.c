#include <stdint.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_452(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract cmsColorSpaceSignature and cmsFloat64Number from the input data
    cmsColorSpaceSignature colorSpaceSignature;
    cmsFloat64Number inkLimit;

    // Copy data into the variables
    memcpy(&colorSpaceSignature, data, sizeof(cmsColorSpaceSignature));
    memcpy(&inkLimit, data + sizeof(cmsColorSpaceSignature), sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateInkLimitingDeviceLink(colorSpaceSignature, inkLimit);

    // Clean up if a valid profile was created
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}