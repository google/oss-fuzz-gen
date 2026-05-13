#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs.
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize variables
    cmsToneCurve *toneCurve = NULL;
    cmsFloat64Number smoothness;

    // Create a tone curve with a single segment
    toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    smoothness = *((cmsFloat64Number *)data);

    // Call the function under test
    cmsBool result = cmsSmoothToneCurve(toneCurve, smoothness);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}