#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

// Define a reasonable size for the cmsToneCurve initialization
#define TONE_CURVE_POINTS 256

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    // Check if the input size is enough to create a tone curve with TONE_CURVE_POINTS
    if (size < TONE_CURVE_POINTS * sizeof(uint16_t)) {
        return 0;
    }

    // Create a tone curve using cmsBuildTabulatedToneCurve16
    cmsToneCurve *originalCurve = cmsBuildTabulatedToneCurve16(NULL, TONE_CURVE_POINTS, (const uint16_t *)data);
    if (originalCurve == NULL) {
        return 0;
    }

    // Call the function under test
    cmsToneCurve *duplicatedCurve = cmsDupToneCurve(originalCurve);

    // Clean up
    if (duplicatedCurve != NULL) {
        cmsFreeToneCurve(duplicatedCurve);
    }
    cmsFreeToneCurve(originalCurve);

    return 0;
}