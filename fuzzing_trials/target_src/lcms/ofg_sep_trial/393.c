#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_393(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE proofingProfile = cmsCreate_sRGBProfile();
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number proofingIntent = INTENT_ABSOLUTE_COLORIMETRIC;
    cmsUInt32Number flags = cmsFLAGS_SOFTPROOFING;

    // Check if data size is sufficient for a minimal RGB input
    if (size < 3) {
        return 0; // Not enough data to form an RGB color
    }

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateProofingTransformTHR(
        context,
        inputProfile,
        inputFormat,
        outputProfile,
        outputFormat,
        proofingProfile,
        intent,
        proofingIntent,
        flags
    );

    // Use the transform with the input data if transform creation was successful
    if (transform != NULL) {
        // Prepare input and output buffers
        uint8_t inputBuffer[3] = { data[0], data[1], data[2] };
        uint8_t outputBuffer[3];

        // Apply the transform
        cmsDoTransform(transform, inputBuffer, outputBuffer, 1);

        // Clean up
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsCloseProfile(proofingProfile);
    cmsDeleteContext(context);

    return 0;
}