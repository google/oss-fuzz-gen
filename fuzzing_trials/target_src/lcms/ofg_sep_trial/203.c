#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_203(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Initialize a cmsCIExyY structure with non-NULL values
    cmsCIExyY whitePoint;
    whitePoint.x = (size > 0) ? (data[0] / 255.0) : 0.3127;
    whitePoint.y = (size > 1) ? (data[1] / 255.0) : 0.3290;
    whitePoint.Y = (size > 2) ? (data[2] / 255.0) : 1.0;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab4ProfileTHR(context, &whitePoint);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

    return 0;
}