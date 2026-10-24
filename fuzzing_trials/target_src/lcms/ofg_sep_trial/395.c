#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_395(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add a dummy stage to the pipeline to ensure it's not empty
    cmsStage *stage = cmsStageAllocIdentity(context, 3);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Call the function-under-test
    cmsStage *firstStage = cmsPipelineGetPtrToFirstStage(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}