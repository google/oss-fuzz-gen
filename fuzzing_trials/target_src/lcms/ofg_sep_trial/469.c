#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_469(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);

    if (pipeline == NULL) {
        return 0; // Allocation failed, exit early
    }

    // Add a stage to the pipeline to ensure it's not NULL
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
    if (stage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage);
    }

    // Fuzz the function
    cmsContext contextID = cmsGetPipelineContextID(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}