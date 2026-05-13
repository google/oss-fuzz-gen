#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_201(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline;
    cmsStage *stage;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a pipeline with at least one stage to ensure it's not NULL
    pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add an identity stage to the pipeline
    cmsStage *identityStage = cmsStageAllocIdentity(context, 3);
    if (identityStage == NULL) {
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }
    cmsPipelineInsertStage(pipeline, cmsAT_END, identityStage);

    // Call the function-under-test
    stage = cmsPipelineGetPtrToLastStage(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}