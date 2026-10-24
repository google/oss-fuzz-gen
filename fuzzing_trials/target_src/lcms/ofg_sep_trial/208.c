#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHTRANSFORM transform = NULL;
    cmsFloat64Number version = 1.0;  // Default version
    cmsUInt32Number flags = 0;  // Default flags

    // Create a dummy color profile
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();

    if (inputProfile == NULL || outputProfile == NULL) {
        if (inputProfile != NULL) cmsCloseProfile(inputProfile);
        if (outputProfile != NULL) cmsCloseProfile(outputProfile);
        return 0;
    }

    // Create a transform
    transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

    if (transform == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE deviceLinkProfile = cmsTransform2DeviceLink(transform, version, flags);

    // Clean up
    if (deviceLinkProfile != NULL) {
        cmsCloseProfile(deviceLinkProfile);
    }
    cmsDeleteTransform(transform);

    return 0;
}