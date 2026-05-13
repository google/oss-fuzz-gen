#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_300(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a stage
    if (size < 4) { // Assuming at least 4 bytes are needed for a minimal stage
        return 0;
    }

    // Create a simple identity stage using LCMS2 API
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 3, 3); // Example with 3 input and output channels
    if (pipeline == NULL) {
        return 0;
    }

    cmsStage* stage = cmsStageAllocIdentity(NULL, 3); // Create an identity stage with 3 channels
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Add the stage to the pipeline
    if (!cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number inputChannels = cmsStageInputChannels(stage);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}