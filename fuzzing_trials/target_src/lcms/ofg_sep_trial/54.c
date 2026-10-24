#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for processing
    if (size < 3) {
        return 0; // Not enough data to form a color
    }

    // Initialize variables for function-under-test
    cmsContext context;
    cmsHPROFILE inputProfile;
    cmsHPROFILE outputProfile;
    cmsUInt32Number inputFormat;
    cmsUInt32Number outputFormat;
    cmsUInt32Number intent;
    cmsUInt32Number flags;

    // Create a new context
    context = cmsCreateContext(NULL, NULL);

    // Initialize input and output profiles
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();

    // Initialize format, intent, and flags with non-zero values
    inputFormat = TYPE_RGB_8;
    outputFormat = TYPE_RGB_8;
    intent = INTENT_PERCEPTUAL;
    flags = 0;

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateTransformTHR(
        context,
        inputProfile,
        inputFormat,
        outputProfile,
        outputFormat,
        intent,
        flags
    );

    // Prepare input and output buffers
    uint8_t inputColor[3] = {data[0], data[1], data[2]};
    uint8_t outputColor[3];

    // Perform the color transformation
    if (transform != NULL) {
        cmsDoTransform(transform, inputColor, outputColor, 1);
        cmsDeleteTransform(transform);
    }

    // Clean up resources
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsDeleteContext(context);

    return 0;
}