#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_385(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read from
    if (size < 3) { // We need at least 3 bytes for cmsCIExyY initialization
        return 0;
    }

    // Initialize cmsCIExyY structure
    cmsCIExyY whitePoint;
    whitePoint.x = (double)data[0] / 255.0;
    whitePoint.y = (double)data[1] / 255.0;
    whitePoint.Y = (double)data[2] / 255.0;

    // Initialize cmsToneCurve structure
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Simple gamma curve

    // Call the function under test
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