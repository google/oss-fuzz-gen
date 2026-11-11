#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext contextID = cmsCreateContext(NULL, NULL);

    // Create a tone curve with a default gamma value
    cmsToneCurve *toneCurve = cmsBuildGamma(contextID, 2.2);
    if (toneCurve == NULL) {
        cmsDeleteContext(contextID);
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIsToneCurveMultisegment(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);
    cmsDeleteContext(contextID);

    return 0;
}