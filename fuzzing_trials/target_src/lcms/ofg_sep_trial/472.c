#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_472(const uint8_t *data, size_t size) {
    // Initialize necessary variables for the function call
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Create input and output profiles using the data provided
    if (size >= sizeof(cmsHPROFILE) * 2) {
        inputProfile = cmsOpenProfileFromMem(data, size / 2);
        outputProfile = cmsOpenProfileFromMem(data + size / 2, size / 2);
    }

    // Ensure profiles are not NULL
    if (inputProfile != NULL && outputProfile != NULL) {
        // Call the function-under-test
        cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, inputFormat,
                                                     outputProfile, outputFormat,
                                                     intent, flags);
        // Clean up
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
    }

    return 0;
}