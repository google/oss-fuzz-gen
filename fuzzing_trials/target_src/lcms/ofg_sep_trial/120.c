#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    cmsCIEXYZ blackPoint;
    cmsHPROFILE hProfile;
    cmsUInt32Number intent = 0;
    cmsUInt32Number flags = 0;

    // Initialize blackPoint with some non-NULL values
    blackPoint.X = 0.0;
    blackPoint.Y = 0.0;
    blackPoint.Z = 0.0;

    // Create a profile using cmsOpenProfileFromMem to ensure it's not NULL
    if (size > 0) {
        hProfile = cmsOpenProfileFromMem(data, size);
    } else {
        return 0;
    }

    if (hProfile != NULL) {
        // Call the function-under-test
        cmsBool result = cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);

        // Close the profile after use
        cmsCloseProfile(hProfile);
    }

    return 0;
}