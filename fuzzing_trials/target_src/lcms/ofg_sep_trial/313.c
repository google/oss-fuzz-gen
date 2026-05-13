#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_313(const uint8_t *data, size_t size) {
    // Ensure we have at least enough data for one cmsUInt16Number
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Determine the number of points for the tone curve
    cmsUInt32Number nPoints = size / sizeof(cmsUInt16Number);

    // Allocate memory for the tone curve points
    cmsUInt16Number *toneCurvePoints = (cmsUInt16Number *)malloc(nPoints * sizeof(cmsUInt16Number));
    if (toneCurvePoints == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Copy the data into the tone curve points
    for (cmsUInt32Number i = 0; i < nPoints; ++i) {
        toneCurvePoints[i] = ((cmsUInt16Number *)data)[i];
    }

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(context, nPoints, toneCurvePoints);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    free(toneCurvePoints);
    cmsDeleteContext(context);

    return 0;
}