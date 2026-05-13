#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_251(const uint8_t *data, size_t size) {
    // Initialize a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (!pipeline) {
        return 0;
    }

    // Add a simple identity transformation for testing purposes
    cmsStage *identityStage = cmsStageAllocIdentity(NULL, 3);
    if (identityStage) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, identityStage);
    }

    // Fuzz the cmsPipelineDup function
    cmsPipeline *duplicatedPipeline = cmsPipelineDup(pipeline);

    // Clean up
    if (duplicatedPipeline) {
        cmsPipelineFree(duplicatedPipeline);
    }
    cmsPipelineFree(pipeline);

    return 0;
}