#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_387(const uint8_t *data, size_t size) {
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsHTRANSFORM transform = NULL;
    cmsContext context;

    // Create input and output profiles
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();

    if (inputProfile == NULL || outputProfile == NULL) {
        if (inputProfile != NULL) {
            cmsCloseProfile(inputProfile);
        }
        if (outputProfile != NULL) {
            cmsCloseProfile(outputProfile);
        }
        return 0;
    }

    // Create a transform
    transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (transform == NULL) {
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Call the function-under-test
    context = cmsGetTransformContextID(transform);

    // Cleanup
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

    return 0;
}