#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include the string.h library for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_353(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize the cmsToneCurve
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Using a common gamma value for initialization
    if (toneCurve == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number inputNumber;
    memcpy(&inputNumber, data, sizeof(cmsFloat64Number));

    // Call the function under test
    cmsFloat64Number result = cmsEstimateGamma(toneCurve, inputNumber);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}