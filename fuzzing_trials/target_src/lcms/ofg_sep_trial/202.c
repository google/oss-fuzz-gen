#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    // Initialize the cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Initialize cmsCIExyY structure
    cmsCIExyY whitePoint;
    whitePoint.x = (size > 0) ? (double)data[0] / 255.0 : 0.3127; // Default D65 white point
    whitePoint.y = (size > 1) ? (double)data[1] / 255.0 : 0.3290;
    whitePoint.Y = (size > 2) ? (double)data[2] / 255.0 : 1.0;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab4ProfileTHR(context, &whitePoint);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

    return 0;
}