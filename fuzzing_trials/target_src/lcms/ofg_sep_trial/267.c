#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_267(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nProfiles = 2; // Number of profiles
    cmsHPROFILE profiles[2];
    cmsBool bInput[2];
    cmsUInt32Number intents[2];
    cmsFloat64Number adapt[2];
    cmsUInt32Number dwFlags = 0;
    cmsUInt32Number cmsFLAGS = 0;
    cmsUInt32Number cmsFLAGS2 = 0;
    cmsUInt32Number cmsFLAGS3 = 0;

    // Use input data to create profiles and set parameters
    profiles[0] = cmsOpenProfileFromMem(data, size / 2);
    profiles[1] = cmsOpenProfileFromMem(data + size / 2, size / 2);

    if (!profiles[0] || !profiles[1]) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize other arrays
    bInput[0] = TRUE;
    bInput[1] = FALSE;
    intents[0] = INTENT_PERCEPTUAL;
    intents[1] = INTENT_RELATIVE_COLORIMETRIC;
    adapt[0] = 1.0;
    adapt[1] = 1.0;

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateExtendedTransform(
        context,
        nProfiles,
        profiles,
        bInput,
        intents,
        adapt,
        profiles[1], // Output profile
        dwFlags,
        cmsFLAGS,
        cmsFLAGS2,
        cmsFLAGS3
    );

    // Cleanup
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(profiles[0]);
    cmsCloseProfile(profiles[1]);
    cmsDeleteContext(context);

    return 0;
}