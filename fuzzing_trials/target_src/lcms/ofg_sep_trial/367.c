#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_367(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a cmsStage object
    if (size < sizeof(cmsStageSignature)) {
        return 0;
    }

    // Create a cmsPipeline to hold the stage
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 0, 0);
    if (pipeline == NULL) {
        return 0;
    }

    // Create a cmsStage object using the lcms2 API
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Add the stage to the pipeline
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Call the function under test
    cmsStageSignature signature = cmsStageType(stage);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}