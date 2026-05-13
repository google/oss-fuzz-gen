#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_340(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsPipeline *pipeline = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a simple pipeline with one stage
    if (context != NULL) {
        pipeline = cmsPipelineAlloc(context, 3, 3);
        if (pipeline != NULL) {
            stage = cmsStageAllocIdentity(context, 3);
            if (stage != NULL) {
                cmsPipelineInsertStage(pipeline, cmsAT_END, stage);
            }
        }
    }

    // Call the function-under-test
    if (stage != NULL) {
        cmsUInt32Number outputChannels = cmsStageOutputChannels(stage);
    }

    // Clean up
    if (pipeline != NULL) {
        cmsPipelineFree(pipeline);
    }
    if (context != NULL) {
        cmsDeleteContext(context);
    }

    return 0;
}