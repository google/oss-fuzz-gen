#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a tone curve with a single segment using the input data
    if (size >= sizeof(double)) {
        double gamma;
        memcpy(&gamma, data, sizeof(double));
        toneCurve = cmsBuildGamma(context, gamma);
    }

    // Ensure toneCurve is not NULL
    if (toneCurve != NULL) {
        // Call the function-under-test
        cmsBool result = cmsIsToneCurveDescending(toneCurve);

        // Clean up
        cmsFreeToneCurve(toneCurve);
    }

    cmsDeleteContext(context);
    return 0;
}