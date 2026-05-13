#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;
    cmsToneCurve *duplicatedCurve = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure size is sufficient to create a tone curve
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Allocate and initialize a tone curve from the input data
    toneCurve = cmsBuildTabulatedToneCurve16(context, (size / sizeof(uint16_t)), (const uint16_t *)data);

    // Ensure toneCurve is not NULL before proceeding
    if (toneCurve != NULL) {
        // Call the function under test
        duplicatedCurve = cmsDupToneCurve(toneCurve);

        // Clean up the duplicated curve
        if (duplicatedCurve != NULL) {
            cmsFreeToneCurve(duplicatedCurve);
        }

        // Clean up the original tone curve
        cmsFreeToneCurve(toneCurve);
    }

    cmsDeleteContext(context);

    return 0;
}