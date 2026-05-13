#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = (cmsContext)1; // Using a non-NULL dummy context
    cmsCIExyY whitePoint;
    cmsToneCurve *toneCurve = NULL;
    cmsHPROFILE profile;

    // Ensure the size is sufficient to extract data for whitePoint
    if (size < 3) {
        return 0;
    }

    // Initialize whitePoint
    whitePoint.x = ((double)data[0] / 255.0);
    whitePoint.y = ((double)data[1] / 255.0);
    whitePoint.Y = ((double)data[2] / 255.0);

    // Create a tone curve using a fixed gamma value
    toneCurve = cmsBuildGamma(context, 2.2); // A simple gamma curve

    // Call the function-under-test
    profile = cmsCreateGrayProfileTHR(context, &whitePoint, toneCurve);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}