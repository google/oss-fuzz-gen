#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(cmsUInt32Number) * 6) {
        return 0;
    }

    // Initialize variables
    cmsHTRANSFORM transform;
    const void *inputBuffer = data + sizeof(cmsUInt32Number) * 6; // Move the input buffer to avoid overlap with parameters
    
    // Extract parameters
    cmsUInt32Number stride = *(const cmsUInt32Number *)(data);
    cmsUInt32Number width = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));
    cmsUInt32Number height = *(const cmsUInt32Number *)(data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number inputStride = *(const cmsUInt32Number *)(data + 3 * sizeof(cmsUInt32Number));
    cmsUInt32Number outputStride = *(const cmsUInt32Number *)(data + 4 * sizeof(cmsUInt32Number));
    cmsUInt32Number flags = *(const cmsUInt32Number *)(data + 5 * sizeof(cmsUInt32Number));

    // Calculate the size needed for outputBuffer
    size_t outputSize = height * outputStride;
    void *outputBuffer = malloc(outputSize);
    if (outputBuffer == NULL) {
        return 0; // Handle memory allocation failure
    }

    // Create a dummy transform to use
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Ensure inputBuffer has enough data
    size_t inputBufferSize = height * inputStride;
    if (size < sizeof(cmsUInt32Number) * 6 + inputBufferSize) {
        free(outputBuffer);
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Call the function under test
    cmsDoTransformLineStride(transform, inputBuffer, outputBuffer, stride, width, height, inputStride, outputStride, flags);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    free(outputBuffer);

    return 0;
}