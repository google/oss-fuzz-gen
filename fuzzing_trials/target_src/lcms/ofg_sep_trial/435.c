#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include this for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_435(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number gammaValue;
    memcpy(&gammaValue, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildGamma(context, gammaValue);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    cmsDeleteContext(context);

    return 0;
}