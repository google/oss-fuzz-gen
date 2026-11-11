#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Initialize the variables needed for cmsCreateRGBProfileTHR
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure data is large enough to extract required values
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(cmsToneCurve *)) {
        return 0;
    }

    // Extract cmsCIExyY from data
    cmsCIExyY whitePoint;
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);

    // Extract cmsCIExyYTRIPLE from data
    cmsCIExyYTRIPLE primaries;
    memcpy(&primaries, data, sizeof(cmsCIExyYTRIPLE));
    data += sizeof(cmsCIExyYTRIPLE);
    size -= sizeof(cmsCIExyYTRIPLE);

    // Create tone curves
    cmsToneCurve *toneCurves[3];
    for (int i = 0; i < 3; i++) {
        // Use a simple gamma curve for each channel
        toneCurves[i] = cmsBuildGamma(context, 2.2);
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, (const cmsToneCurve **)toneCurves);

    // Cleanup
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    for (int i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }
    cmsDeleteContext(context);

    return 0;
}