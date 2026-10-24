#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_392(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Not enough data to proceed
    }

    cmsContext context;
    cmsHPROFILE inputProfile, outputProfile, proofingProfile;
    cmsUInt32Number inputFormat, outputFormat, proofIntent, flags, intent;
    cmsHTRANSFORM transform;

    // Initialize context and profiles
    context = cmsCreateContext(NULL, NULL);
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();
    proofingProfile = cmsCreate_sRGBProfile();

    // Initialize format, intents, and flags
    inputFormat = TYPE_RGB_8;
    outputFormat = TYPE_RGB_8;
    proofIntent = INTENT_RELATIVE_COLORIMETRIC;
    intent = INTENT_PERCEPTUAL;
    flags = cmsFLAGS_SOFTPROOFING;

    // Call the function under test
    transform = cmsCreateProofingTransformTHR(
        context,
        inputProfile,
        inputFormat,
        outputProfile,
        outputFormat,
        proofingProfile,
        proofIntent,
        intent,
        flags
    );

    if (transform != NULL) {
        // Use the transform to process the input data
        uint8_t output[3]; // Buffer for transformed data
        cmsDoTransform(transform, data, output, 1); // Transform 1 pixel

        // Optionally, do something with the output to ensure it's used
        // For fuzzing, just ensure the function is called
    }

    // Cleanup
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsCloseProfile(proofingProfile);
    cmsDeleteContext(context);

    return 0;
}