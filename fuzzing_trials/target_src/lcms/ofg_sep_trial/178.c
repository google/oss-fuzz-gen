#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsHPROFILE proofingProfile = NULL;
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number proofingIntent = INTENT_RELATIVE_COLORIMETRIC;
    cmsUInt32Number transformIntent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Create dummy profiles for testing
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();
    proofingProfile = cmsCreate_sRGBProfile();

    // Ensure profiles were created successfully
    if (inputProfile == NULL || outputProfile == NULL || proofingProfile == NULL) {
        if (inputProfile) cmsCloseProfile(inputProfile);
        if (outputProfile) cmsCloseProfile(outputProfile);
        if (proofingProfile) cmsCloseProfile(proofingProfile);
        return 0;
    }

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateProofingTransform(
        inputProfile, inputFormat,
        outputProfile, outputFormat,
        proofingProfile, proofingIntent,
        transformIntent, flags
    );

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsCloseProfile(proofingProfile);

    return 0;
}