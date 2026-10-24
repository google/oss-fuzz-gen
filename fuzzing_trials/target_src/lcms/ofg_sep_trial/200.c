#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_200(const uint8_t *data, size_t size) {
    if (size < 3 * sizeof(float)) {
        return 0; // Not enough data to proceed
    }

    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a pipeline with a specific number of stages
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);

    // Add a dummy stage to the pipeline for testing
    cmsStage *stage = cmsStageAllocIdentity(context, 3);
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Call the function-under-test
    cmsStage *lastStage = cmsPipelineGetPtrToLastStage(pipeline);

    // Use the input data to simulate some processing
    float input[3];
    for (int i = 0; i < 3; i++) {
        input[i] = ((float *)data)[i];
    }
    cmsPipelineEvalFloat(input, input, pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}