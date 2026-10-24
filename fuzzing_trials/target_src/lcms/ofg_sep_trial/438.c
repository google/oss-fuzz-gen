#include <stdint.h>
#include <lcms2.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy

int LLVMFuzzerTestOneInput_438(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve *toneCurves[3];

    // Calculate the size required for the input data
    size_t required_size = sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(double);

    // Ensure data is large enough to populate the structures
    if (size < required_size) {
        return 0;
    }

    // Populate whitePoint from data
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));

    // Move data pointer forward
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);

    // Populate primaries from data
    memcpy(&primaries, data, sizeof(cmsCIExyYTRIPLE));

    // Move data pointer forward
    data += sizeof(cmsCIExyYTRIPLE);
    size -= sizeof(cmsCIExyYTRIPLE);

    // Initialize tone curves
    for (int i = 0; i < 3; i++) {
        toneCurves[i] = cmsBuildGamma(NULL, 2.2); // Use a fixed gamma value for simplicity
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateRGBProfile(&whitePoint, &primaries, toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    for (int i = 0; i < 3; i++) {
        cmsFreeToneCurve(toneCurves[i]);
    }

    return 0;
}