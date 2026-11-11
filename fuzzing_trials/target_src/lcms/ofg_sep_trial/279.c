#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_279(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHTRANSFORM transform;
    cmsUInt32Number inputFormat;
    cmsUInt32Number outputFormat;
    cmsBool result;

    // Ensure size is sufficient for extracting input and output formats
    if (size < 2 * sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the transform (dummy initialization for fuzzing)
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    cmsCloseProfile(hProfile);

    // Extract input and output formats from the data
    inputFormat = *(const cmsUInt32Number *)data;
    outputFormat = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    result = cmsChangeBuffersFormat(transform, inputFormat, outputFormat);

    // Clean up the transform
    cmsDeleteTransform(transform);

    return 0;
}