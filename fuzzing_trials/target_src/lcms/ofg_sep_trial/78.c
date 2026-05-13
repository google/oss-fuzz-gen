#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <string.h>

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Check if the size is large enough to extract meaningful data
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(double)) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables for the function parameters
    cmsContext context = NULL; // Assuming a default context
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve *toneCurves[3];

    // Use fuzzing data to initialize the whitePoint
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);

    // Use fuzzing data to initialize the primaries
    memcpy(&primaries, data, sizeof(cmsCIExyYTRIPLE));
    data += sizeof(cmsCIExyYTRIPLE);
    size -= sizeof(cmsCIExyYTRIPLE);

    // Use fuzzing data to create tone curves for each channel
    for (int i = 0; i < 3; i++) {
        if (size < sizeof(double)) {
            return 0; // Not enough data to proceed
        }
        double gamma = *((double *)data);
        toneCurves[i] = cmsBuildGamma(context, gamma);
        data += sizeof(double);
        size -= sizeof(double);
    }

    // Call the function under test
    cmsHPROFILE profile = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, (const cmsToneCurve **)toneCurves);

    // Clean up the tone curves
    for (int i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }

    // If a profile was created, release it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}