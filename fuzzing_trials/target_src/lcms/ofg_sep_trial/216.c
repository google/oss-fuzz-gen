#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_216(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;

    // Ensure the size is sufficient for creating a tone curve
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Create a tone curve using the data provided
    cmsFloat32Number gamma = *(cmsFloat32Number *)data;
    toneCurve = cmsBuildGamma(NULL, gamma);

    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool isLinear = cmsIsToneCurveLinear(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}