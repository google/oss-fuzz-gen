#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    // Initialize the context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure there's enough data to work with
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsToneCurve *)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract cmsUInt32Number from data
    cmsUInt32Number numCurves = *((cmsUInt32Number *)data);
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Allocate memory for cmsToneCurve pointers
    const cmsToneCurve **toneCurves = (const cmsToneCurve **)malloc(numCurves * sizeof(cmsToneCurve *));
    if (toneCurves == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize each cmsToneCurve
    for (cmsUInt32Number i = 0; i < numCurves; i++) {
        toneCurves[i] = cmsBuildGamma(context, 2.2);  // Example gamma value
        if (toneCurves[i] == NULL) {
            // Free previously allocated tone curves
            for (cmsUInt32Number j = 0; j < i; j++) {
                cmsFreeToneCurve(toneCurves[j]);
            }
            free(toneCurves);
            cmsDeleteContext(context);
            return 0;
        }
    }

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocToneCurves(context, numCurves, toneCurves);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
    for (cmsUInt32Number i = 0; i < numCurves; i++) {
        cmsFreeToneCurve((cmsToneCurve *)toneCurves[i]);
    }
    free(toneCurves);
    cmsDeleteContext(context);

    return 0;
}