#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_306(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Perform some operations on the pipeline if needed
    // For example, you could add stages or manipulate the pipeline here
    // Ensure that the input data is utilized meaningfully
    if (size > 0) {
        // Example operation: add a stage using the input data
        cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
        if (stage != NULL) {
            cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage);
        }
    }

    // Free the pipeline using the function-under-test
    cmsPipelineFree(pipeline);

    return 0;
}