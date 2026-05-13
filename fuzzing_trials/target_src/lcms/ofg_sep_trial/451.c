#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_451(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;

    // Initialize a dummy color transform for fuzzing
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    
    if (inputProfile == NULL || outputProfile == NULL) {
        if (inputProfile != NULL) cmsCloseProfile(inputProfile);
        if (outputProfile != NULL) cmsCloseProfile(outputProfile);
        return 0;
    }

    transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

    if (transform != NULL) {
        // Call the function under test with non-null input
        if (size >= 3) { // Ensure there is enough data for at least one RGB pixel
            cmsDoTransform(transform, data, data, size / 3);
        }
        cmsDeleteTransform(transform);
    }

    return 0;
}