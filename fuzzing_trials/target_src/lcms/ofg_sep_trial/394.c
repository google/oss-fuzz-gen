#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_394(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;
    cmsStage *stage = NULL;

    // Initialize a cmsPipeline with a non-NULL value
    pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Add a stage to the pipeline to ensure it's not empty
    cmsStage *identityStage = cmsStageAllocIdentity(NULL, 3);
    if (identityStage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, identityStage);
    }

    // Call the function under test
    stage = cmsPipelineGetPtrToFirstStage(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}