#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract all required parameters
    if (size < sizeof(cmsUInt32Number) * 4) {
        return 0;
    }

    // Initialize a context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create dummy profiles
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();

    // Extract cmsUInt32Number parameters from the data
    cmsUInt32Number inputFormat = *(const cmsUInt32Number *)data;
    cmsUInt32Number outputFormat = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));
    cmsUInt32Number intent = *(const cmsUInt32Number *)(data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number flags = *(const cmsUInt32Number *)(data + 3 * sizeof(cmsUInt32Number));

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

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsDeleteContext(context);

    return 0;
}