#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsIsToneCurveMonotonic
int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a cmsToneCurve
    if (size < sizeof(uint16_t) * 2) {
        return 0;
    }

    // Allocate memory for the tone curve
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(NULL, size / sizeof(uint16_t), (const uint16_t *)data);

    // Check if the tone curve is monotonic
    if (toneCurve != NULL) {
        cmsBool result = cmsIsToneCurveMonotonic(toneCurve);
        (void)result; // Use the result to avoid unused variable warning

        // Free the tone curve
        cmsFreeToneCurve(toneCurve);
    }

    return 0;
}