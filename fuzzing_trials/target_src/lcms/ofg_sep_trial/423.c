#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_423(const uint8_t *data, size_t size) {
    if (size < 3) return 0; // Ensure there's enough data for processing

    cmsHPROFILE profiles[3];
    cmsUInt32Number nProfiles = 3;
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Initialize profiles with some default profiles
    profiles[0] = cmsCreate_sRGBProfile();
    profiles[1] = cmsCreateLab4Profile(NULL);
    profiles[2] = cmsCreateXYZProfile();

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(
        profiles, nProfiles, inputFormat, outputFormat, intent, flags);

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        if (profiles[i] != NULL) {
            cmsCloseProfile(profiles[i]);
        }
    }

    return 0;
}