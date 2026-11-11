#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a tone curve with at least 2 segments to ensure it's not NULL
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(context, 2, (const uint16_t *)data);

    // Call the function-under-test
    cmsBool result = cmsIsToneCurveMultisegment(toneCurve);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    cmsDeleteContext(context);

    return 0;
}