#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    // Initialize variables for cmsDoTransform
    cmsHTRANSFORM transform;
    cmsHPROFILE inputProfile, outputProfile;
    cmsUInt32Number inputFormat, outputFormat;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;
    cmsUInt32Number numPixels = size / 4; // Assume each pixel is 4 bytes (e.g., RGBA)

    // Allocate input and output buffers
    void *inputBuffer = malloc(size);
    void *outputBuffer = malloc(size);

    // Ensure inputBuffer and outputBuffer are not NULL
    if (inputBuffer == NULL || outputBuffer == NULL) {
        free(inputBuffer);
        free(outputBuffer);
        return 0;
    }

    // Copy data to inputBuffer
    memcpy(inputBuffer, data, size);

    // Create a dummy input and output profile
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();

    // Define input and output formats
    inputFormat = TYPE_RGBA_8;
    outputFormat = TYPE_RGBA_8;

    // Create a color transform
    transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);

    // Call the function-under-test
    cmsDoTransform(transform, inputBuffer, outputBuffer, numPixels);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    free(inputBuffer);
    free(outputBuffer);

    return 0;
}