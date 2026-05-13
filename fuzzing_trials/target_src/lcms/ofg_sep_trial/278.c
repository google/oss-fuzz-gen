#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_278(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;
    cmsUInt32Number inputFormat;
    cmsUInt32Number outputFormat;
    cmsHPROFILE hProfile;

    // Initialize Little CMS
    cmsSetLogErrorHandler(NULL);

    // Create a dummy profile for the transformation
    hProfile = cmsCreate_sRGBProfile();

    // Create a transform with the dummy profile
    transform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Ensure that the transform is valid
    if (transform == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Use the first few bytes of data to set input and output formats
    if (size >= 8) {
        inputFormat = *(cmsUInt32Number *)data;
        outputFormat = *(cmsUInt32Number *)(data + 4);
    } else {
        inputFormat = TYPE_RGB_8; // Default format
        outputFormat = TYPE_RGB_8; // Default format
    }

    // Call the function under test
    cmsBool result = cmsChangeBuffersFormat(transform, inputFormat, outputFormat);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(hProfile);

    return 0;
}