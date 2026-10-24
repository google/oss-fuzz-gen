#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsToneCurve *curve1 = NULL;
    cmsToneCurve *curve2 = NULL;
    cmsToneCurve *result = NULL;
    cmsUInt32Number location = 0;

    if (size < sizeof(cmsUInt32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create tone curves from the input data
    curve1 = cmsBuildGamma(context, 2.2);  // Example gamma value
    curve2 = cmsBuildGamma(context, 2.4);  // Another example gamma value

    // Extract a cmsUInt32Number from data
    location = *(const cmsUInt32Number *)data;

    // Call the function under test
    result = cmsJoinToneCurve(context, curve1, curve2, location);

    // Clean up
    if (result != NULL) {
        cmsFreeToneCurve(result);
    }
    if (curve1 != NULL) {
        cmsFreeToneCurve(curve1);
    }
    if (curve2 != NULL) {
        cmsFreeToneCurve(curve2);
    }
    cmsDeleteContext(context);

    return 0;
}