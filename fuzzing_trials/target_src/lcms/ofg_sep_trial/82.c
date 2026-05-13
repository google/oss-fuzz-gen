#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsIsToneCurveMonotonic
int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a tone curve
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Create a tone curve with at least one segment
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(NULL, 1, (const uint16_t *)data);

    // Call the function-under-test
    if (toneCurve != NULL) {
        cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);
        // Use the result to prevent compiler optimizations
        if (isMonotonic) {
            // Do something if monotonic
        }
        // Free the tone curve
        cmsFreeToneCurve(toneCurve);
    }

    return 0;
}