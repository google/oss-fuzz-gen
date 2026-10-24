#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_207(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number)) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    cmsHTRANSFORM transform;
    cmsFloat64Number version;
    cmsUInt32Number flags;

    // Create a dummy color profile and transform
    cmsHPROFILE srcProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE dstProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(srcProfile, TYPE_RGB_8, dstProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Extract version and flags from data
    version = *(cmsFloat64Number *)data;
    flags = *(cmsUInt32Number *)(data + sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsHPROFILE deviceLinkProfile = cmsTransform2DeviceLink(transform, version, flags);

    // Clean up
    if (deviceLinkProfile != NULL) {
        cmsCloseProfile(deviceLinkProfile);
    }
    cmsDeleteTransform(transform);
    cmsCloseProfile(srcProfile);
    cmsCloseProfile(dstProfile);

    return 0;
}