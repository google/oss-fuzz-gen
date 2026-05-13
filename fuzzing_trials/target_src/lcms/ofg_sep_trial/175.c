#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure size is sufficient for cmsCIExyY initialization
    if (size < sizeof(cmsCIExyY)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize cmsCIExyY
    cmsCIExyY whitePoint;
    whitePoint.x = (double)data[0] / 255.0;
    whitePoint.y = (double)data[1] / 255.0;
    whitePoint.Y = (double)data[2] / 255.0;

    // Initialize cmsToneCurve
    cmsToneCurve *toneCurve = cmsBuildGamma(context, 2.2); // Example gamma value

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateGrayProfileTHR(context, &whitePoint, toneCurve);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsFreeToneCurve(toneCurve);
    cmsDeleteContext(context);

    return 0;
}