// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineAlloc at cmslut.c:1377:24 in lcms2.h
// cmsStageAllocIdentity at cmslut.c:70:21 in lcms2.h
// cmsPipelineInsertStage at cmslut.c:1519:15 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineDup at cmslut.c:1464:24 in lcms2.h
// cmsPipelineCat at cmslut.c:1612:20 in lcms2.h
// _cmsPipelineSetOptimizationParameters at cmslut.c:1674:16 in lcms2_plugin.h
// cmsPipelineCheckAndRetreiveStages at cmslut.c:110:20 in lcms2.h
// cmsPipelineSetSaveAs8bitsFlag at cmslut.c:1637:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>
#include <lcms2_plugin.h>

static cmsPipeline* createDummyPipeline() {
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline) {
        cmsStage* stage = cmsStageAllocIdentity(NULL, 3);
        if (stage) {
            cmsPipelineInsertStage(pipeline, cmsAT_END, stage);
        }
    }
    return pipeline;
}

static void freePipeline(cmsPipeline* pipeline) {
    if (pipeline) {
        cmsPipelineFree(pipeline);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cmsPipeline* pipeline1 = createDummyPipeline();
    cmsPipeline* pipeline2 = createDummyPipeline();

    if (pipeline1 && pipeline2) {
        // Test cmsPipelineDup
        cmsPipeline* dupPipeline = cmsPipelineDup(pipeline1);
        if (dupPipeline) {
            freePipeline(dupPipeline);
        }

        // Test cmsPipelineCat
        cmsPipelineCat(pipeline1, pipeline2);

        // Test _cmsPipelineSetOptimizationParameters
        _cmsPipelineSetOptimizationParameters(pipeline1, NULL, NULL, NULL, NULL);

        // Test cmsPipelineCheckAndRetreiveStages
        cmsStage* stages[1];
        cmsPipelineCheckAndRetreiveStages(pipeline1, 1, cmsSigIdentityElemType, &stages[0]);

        // Test cmsPipelineSetSaveAs8bitsFlag
        cmsPipelineSetSaveAs8bitsFlag(pipeline1, (cmsBool)(Data[0] % 2));
    }

    freePipeline(pipeline1);
    freePipeline(pipeline2);

    return 0;
}