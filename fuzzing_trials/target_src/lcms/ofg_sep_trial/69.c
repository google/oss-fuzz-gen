#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsUInt32Number nPoints = 256; // Example value for the number of points

    // Ensure that size is sufficient to create a tone curve
    if (size < nPoints * sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Create a tone curve from the input data
    cmsToneCurve *inputCurve = cmsBuildTabulatedToneCurve16(NULL, nPoints, (const cmsUInt16Number *)data);

    // Check if the tone curve was created successfully
    if (inputCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsToneCurve *reversedCurve = cmsReverseToneCurveEx(nPoints, inputCurve);

    // Clean up
    if (reversedCurve != NULL) {
        cmsFreeToneCurve(reversedCurve);
    }
    cmsFreeToneCurve(inputCurve);

    return 0;
}