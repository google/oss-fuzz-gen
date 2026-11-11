#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsEstimateGamma
int LLVMFuzzerTestOneInput_354(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize variables
    cmsToneCurve *toneCurve;
    cmsFloat64Number value;

    // Create a dummy tone curve for testing
    toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve == NULL) {
        return 0;
    }

    // Read a cmsFloat64Number from the input data
    value = *((cmsFloat64Number *)data);

    // Call the function-under-test
    cmsFloat64Number result = cmsEstimateGamma(toneCurve, value);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}