#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Initialize the necessary variables
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
    cmsStage *unlinkedStage = NULL;
    
    // Ensure the pipeline and stage are not NULL
    if (pipeline == NULL || stage == NULL) {
        return 0;
    }

    // Add the stage to the pipeline
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Use the input data to determine the stage location
    cmsStageLoc loc = (cmsStageLoc)(data[0] % 2); // Use the first byte to determine location

    // Call the function-under-test
    cmsPipelineUnlinkStage(pipeline, loc, &unlinkedStage);

    // Clean up
    if (unlinkedStage != NULL) {
        cmsStageFree(unlinkedStage);
    }
    cmsPipelineFree(pipeline);

    return 0;
}