#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_377(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);

    // Check if pipeline creation was successful
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add a dummy stage to the pipeline to ensure it is not empty
    cmsStage *identityStage = cmsStageAllocIdentity(context, 3);
    if (identityStage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, identityStage);
    }

    // Call the function-under-test
    cmsUInt32Number stageCount = cmsPipelineStageCount(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}