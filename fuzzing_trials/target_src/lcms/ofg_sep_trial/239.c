#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
    // Initialize the cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Initialize cmsCIExyY structure with non-null values
    cmsCIExyY whitePoint;
    whitePoint.x = 0.3127; // D65 standard illuminant
    whitePoint.y = 0.3290;
    whitePoint.Y = 1.0;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab2ProfileTHR(context, &whitePoint);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

    return 0;
}