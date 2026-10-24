#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read a double value
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Create a cmsToneCurve object
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number value;
    memcpy(&value, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsBool result = cmsSmoothToneCurve(toneCurve, value);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}