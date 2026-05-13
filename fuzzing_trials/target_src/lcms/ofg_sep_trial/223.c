#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_223(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nCurves = 2; // Number of tone curves to allocate
    cmsToneCurve *toneCurves[2];

    // Initialize tone curves with some default values
    toneCurves[0] = cmsBuildGamma(context, (double)data[0] / 10.0 + 1.0);
    toneCurves[1] = cmsBuildGamma(context, (double)data[1] / 10.0 + 1.0);

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocToneCurves(context, nCurves, (const cmsToneCurve **)toneCurves);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }

    for (cmsUInt32Number i = 0; i < nCurves; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }

    cmsDeleteContext(context);

    return 0;
}