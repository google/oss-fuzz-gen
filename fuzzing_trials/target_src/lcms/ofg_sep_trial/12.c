#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHTRANSFORM transform = NULL;
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Create dummy profiles if size is sufficient
    if (size > 0) {
        inputProfile = cmsCreate_sRGBProfile();
        outputProfile = cmsCreate_sRGBProfile();
    }

    // Create a transform if profiles are valid
    if (inputProfile != NULL && outputProfile != NULL) {
        transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);
    }

    // Call the function under test
    if (transform != NULL) {
        cmsUInt32Number outputFormatResult = cmsGetTransformOutputFormat(transform);
    }

    // Cleanup
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    if (inputProfile != NULL) {
        cmsCloseProfile(inputProfile);
    }
    if (outputProfile != NULL) {
        cmsCloseProfile(outputProfile);
    }

    return 0;
}