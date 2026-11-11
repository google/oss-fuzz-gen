#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    cmsCIEXYZ blackPoint;
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;

    // Initialize the blackPoint with some values
    blackPoint.X = 0.0;
    blackPoint.Y = 0.0;
    blackPoint.Z = 0.0;

    // Create a profile from memory
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Set intent and flags to some non-zero values
    intent = INTENT_PERCEPTUAL;
    flags = cmsFLAGS_BLACKPOINTCOMPENSATION;

    // Call the function-under-test
    cmsBool result = cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}