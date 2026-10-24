#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_277(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a cmsToneCurve
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Create a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Initialize a cmsToneCurve with some parameters
    cmsToneCurve* toneCurve = cmsBuildGamma(context, 2.2); // Example gamma value

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