#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_250(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsToneCurve *curve1 = NULL;
    cmsToneCurve *curve2 = NULL;
    cmsUInt32Number location = 0;

    // Initialize context
    context = cmsCreateContext(NULL, NULL);

    // Ensure the size is sufficient to create tone curves
    if (size < 2) {
        return 0;
    }

    // Create two tone curves from the input data
    curve1 = cmsBuildGamma(context, 2.2);
    curve2 = cmsBuildGamma(context, 1.8);

    // Use a part of the input data to determine the location
    location = (cmsUInt32Number)data[0];

    // Call the function under test
    cmsToneCurve *resultCurve = cmsJoinToneCurve(context, curve1, curve2, location);

    // Clean up
    if (curve1 != NULL) {
        cmsFreeToneCurve(curve1);
    }
    if (curve2 != NULL) {
        cmsFreeToneCurve(curve2);
    }
    if (resultCurve != NULL) {
        cmsFreeToneCurve(resultCurve);
    }
    cmsDeleteContext(context);

    return 0;
}