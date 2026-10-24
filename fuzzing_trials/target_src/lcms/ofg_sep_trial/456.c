#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_456(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;

    // Create a tone curve using the data provided, ensuring it is not NULL
    if (size > 0) {
        toneCurve = cmsBuildGamma(NULL, (double)data[0] / 255.0);
    }

    // Call the function-under-test
    cmsFreeToneCurve(toneCurve);

    return 0;
}