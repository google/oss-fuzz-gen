#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_391(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline1 = cmsPipelineAlloc(NULL, 3, 3);
    cmsPipeline *pipeline2 = cmsPipelineAlloc(NULL, 3, 3);

    if (pipeline1 == NULL || pipeline2 == NULL) {
        if (pipeline1 != NULL) cmsPipelineFree(pipeline1);
        if (pipeline2 != NULL) cmsPipelineFree(pipeline2);
        return 0;
    }

    // Add some dummy stages to the pipelines
    cmsStage *stage1 = cmsStageAllocIdentity(NULL, 3);
    cmsStage *stage2 = cmsStageAllocIdentity(NULL, 3);

    if (stage1 != NULL && stage2 != NULL) {
        cmsPipelineInsertStage(pipeline1, cmsAT_END, stage1);
        cmsPipelineInsertStage(pipeline2, cmsAT_END, stage2);

        // Fuzz the function
        cmsBool result = cmsPipelineCat(pipeline1, pipeline2);

        // Use the result in some way to avoid compiler optimizations
        if (result) {
            // Do something with the result if needed
        }
    }

    // Clean up
    cmsPipelineFree(pipeline1);
    cmsPipelineFree(pipeline2);

    return 0;
}