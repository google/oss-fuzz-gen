#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_374(const uint8_t *data, size_t size) {
    // Initialize cmsStage object
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsStage *stage = cmsStageAllocIdentity(context, 3);
    if (stage == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    const cmsStage *nextStage = cmsStageNext(stage);

    // Clean up
    cmsStageFree(stage);
    cmsDeleteContext(context);

    return 0;
}