#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <string.h> // For memcpy

int LLVMFuzzerTestOneInput_439(const uint8_t *data, size_t size) {
    // Initialize parameters for cmsCreateRGBProfile
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve *toneCurves[3];

    // Ensure data is large enough to populate our structures
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(float)) {
        return 0;
    }

    // Populate whitePoint and primaries using data
    const uint8_t *ptr = data;
    memcpy(&whitePoint, ptr, sizeof(cmsCIExyY));
    ptr += sizeof(cmsCIExyY);

    memcpy(&primaries, ptr, sizeof(cmsCIExyYTRIPLE));
    ptr += sizeof(cmsCIExyYTRIPLE);

    // Initialize tone curves
    for (int i = 0; i < 3; i++) {
        toneCurves[i] = cmsBuildGamma(NULL, 2.2); // Using a standard gamma value for simplicity
    }

    // Call the function under test
    cmsHPROFILE profile = cmsCreateRGBProfile(&whitePoint, &primaries, toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    for (int i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }

    return 0;
}