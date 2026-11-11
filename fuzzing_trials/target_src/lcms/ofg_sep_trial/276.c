#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_276(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a cmsToneCurve
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Create a memory context for LittleCMS
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a tone curve using the input data
    cmsToneCurve *toneCurve = cmsBuildGamma(context, 2.2); // Using a gamma value of 2.2 as an example
    if (toneCurve == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsInt32Number parametricType = cmsGetToneCurveParametricType(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);
    cmsDeleteContext(context);

    return 0;
}