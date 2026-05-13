#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include this library for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_191(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a cmsFloat32Number
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Initialize a cmsToneCurve object
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Using a gamma value of 2.2 as an example

    // Extract a cmsFloat32Number from the data
    cmsFloat32Number inputFloat;
    memcpy(&inputFloat, data, sizeof(cmsFloat32Number));

    // Call the function under test
    cmsFloat32Number result = cmsEvalToneCurveFloat(toneCurve, inputFloat);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}