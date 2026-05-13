#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_443(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for the operations
    if (size < sizeof(double)) {
        return 0;
    }

    // Interpret the first part of the data as a double value for gamma
    double gamma = *((double*)data);

    // Declare and initialize the cmsToneCurve pointers using the gamma value
    cmsToneCurve *toneCurve1 = cmsBuildGamma(NULL, gamma);
    cmsToneCurve *toneCurve2 = cmsBuildGamma(NULL, gamma);
    cmsToneCurve *toneCurve3 = cmsBuildGamma(NULL, gamma);

    // Check if tone curves are created successfully
    if (toneCurve1 == NULL || toneCurve2 == NULL || toneCurve3 == NULL) {
        return 0;
    }

    // Create an array of cmsToneCurve pointers
    cmsToneCurve *toneCurveArray[3] = {toneCurve1, toneCurve2, toneCurve3};

    // Call the function-under-test
    cmsFreeToneCurveTriple(toneCurveArray);

    return 0;
}