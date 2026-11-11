#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_220(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsColorSpaceSignature colorSpaceSignature = cmsSigRgbData; // Example color space
    cmsFloat64Number limit = 100.0; // Example limit value

    // Ensure the size is sufficient for fuzzing
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Use the data provided for fuzzing
    limit = *((cmsFloat64Number*)data);

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateInkLimitingDeviceLinkTHR(context, colorSpaceSignature, limit);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

    return 0;
}