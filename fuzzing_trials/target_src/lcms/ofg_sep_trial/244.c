#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_244(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE *profiles = NULL;
    cmsUInt32Number nProfiles = 2; // Assuming at least 2 profiles for transformation
    cmsUInt32Number inputFormat = TYPE_RGB_8; // Example format
    cmsUInt32Number outputFormat = TYPE_RGB_8; // Example format
    cmsUInt32Number intent = INTENT_PERCEPTUAL; // Example intent
    cmsUInt32Number flags = 0; // No flags

    // Allocate memory for profiles
    profiles = (cmsHPROFILE *)malloc(nProfiles * sizeof(cmsHPROFILE));
    if (profiles == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create sample profiles
    profiles[0] = cmsCreate_sRGBProfile();
    profiles[1] = cmsCreate_sRGBProfile();

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransformTHR(
        context, profiles, nProfiles, inputFormat, outputFormat, intent, flags);

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        if (profiles[i] != NULL) {
            cmsCloseProfile(profiles[i]);
        }
    }
    free(profiles);
    cmsDeleteContext(context);

    return 0;
}