#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_436(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for extracting a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize the cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the data
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