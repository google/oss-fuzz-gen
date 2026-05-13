#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_373(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for some operation
    if (size < 1) {
        return 0;
    }

    // Create a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a dummy cmsStage using LCMS API
    cmsStage *stage = cmsStageAllocIdentity(context, 3);
    if (stage == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsStage *nextStage = cmsStageNext(stage);

    // Clean up
    cmsStageFree(stage);
    cmsDeleteContext(context);

    return 0;
}