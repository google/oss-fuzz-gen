#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_384(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract necessary parameters
    if (size < 3 * sizeof(double)) {
        return 0;
    }

    // Initialize cmsCIExyY structure
    cmsCIExyY whitePoint;
    whitePoint.x = *((double *)data);
    whitePoint.y = *((double *)(data + sizeof(double)));
    whitePoint.Y = *((double *)(data + 2 * sizeof(double)));

    // Initialize cmsToneCurve structure
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateGrayProfile(&whitePoint, toneCurve);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }

    return 0;
}