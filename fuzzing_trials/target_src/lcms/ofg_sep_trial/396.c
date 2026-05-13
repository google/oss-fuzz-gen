#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_396(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;

    // Create a dummy pipeline with at least one stage to avoid NULL
    pipeline = cmsPipelineAlloc(NULL, 3, 3);  // 3 input channels, 3 output channels
    if (pipeline == NULL) {
        return 0;
    }

    // Add a simple stage to the pipeline
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);  // Identity stage with 3 channels
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Call the function-under-test
    cmsUInt32Number outputChannels = cmsPipelineOutputChannels(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}