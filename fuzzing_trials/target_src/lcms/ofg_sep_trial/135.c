#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;
    cmsHPROFILE inputProfile, outputProfile;
    cmsUInt32Number inputFormat, outputFormat;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Initialize the profiles
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();

    // Initialize formats
    inputFormat = TYPE_RGB_8;
    outputFormat = TYPE_RGB_8;

    // Create a transform
    transform = cmsCreateTransform(inputProfile, inputFormat,
                                   outputProfile, outputFormat,
                                   intent, flags);

    // Check if the transform was created successfully
    if (transform == NULL) {
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Allocate memory for input and output buffers
    uint8_t *inputBuffer = (uint8_t *)malloc(size);
    uint8_t *outputBuffer = (uint8_t *)malloc(size);

    if (inputBuffer == NULL || outputBuffer == NULL) {
        free(inputBuffer);
        free(outputBuffer);
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Copy the fuzzer data to the input buffer
    memcpy(inputBuffer, data, size);

    // Apply the transform
    cmsDoTransform(transform, inputBuffer, outputBuffer, size / 3);

    // Clean up
    free(inputBuffer);
    free(outputBuffer);
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

    return 0;
}