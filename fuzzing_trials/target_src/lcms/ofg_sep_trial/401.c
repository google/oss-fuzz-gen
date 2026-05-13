#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_401(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to create a tone curve
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Create a tone curve with some default parameters
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsToneCurve *reversedCurve = cmsReverseToneCurve(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);
    if (reversedCurve != NULL) {
        cmsFreeToneCurve(reversedCurve);
    }

    return 0;
}