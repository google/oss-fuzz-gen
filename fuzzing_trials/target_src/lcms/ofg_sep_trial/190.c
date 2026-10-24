#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract a cmsFloat32Number
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Initialize a cmsToneCurve object
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Using a gamma value of 2.2 as an example
    if (toneCurve == NULL) {
        return 0;
    }

    // Extract a cmsFloat32Number from the input data
    cmsFloat32Number inputNumber;
    memcpy(&inputNumber, data, sizeof(cmsFloat32Number));

    // Call the function-under-test
    cmsFloat32Number result = cmsEvalToneCurveFloat(toneCurve, inputNumber);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}