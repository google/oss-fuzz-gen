#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_257(const uint8_t *data, size_t size) {
    // Initialize a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Add a stage to the pipeline to ensure it is not empty
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
    if (stage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage);
    }

    // Use the first byte of data as the cmsUInt32Number parameter
    cmsUInt32Number stageIndex = 0;
    if (size > 0) {
        stageIndex = data[0];
    }

    // Call the function-under-test
    cmsBool result = cmsPipelineCheckAndRetreiveStages(pipeline, stageIndex, NULL);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}