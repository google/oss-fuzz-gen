// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineAlloc at cmslut.c:1377:24 in lcms2.h
// cmsStageAllocIdentity at cmslut.c:70:21 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineInsertStage at cmslut.c:1519:15 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineDup at cmslut.c:1464:24 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineCat at cmslut.c:1612:20 in lcms2.h
// cmsPipelineEval16 at cmslut.c:1447:16 in lcms2.h
// cmsPipelineSetSaveAs8bitsFlag at cmslut.c:1637:19 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static cmsPipeline* createDummyPipeline() {
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (!pipeline) return NULL;

    // Dummy stage for testing
    cmsStage* stage = cmsStageAllocIdentity(NULL, 3);
    if (!stage) {
        cmsPipelineFree(pipeline);
        return NULL;
    }

    if (!cmsPipelineInsertStage(pipeline, cmsAT_END, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        return NULL;
    }

    return pipeline;
}

int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy pipeline for testing
    cmsPipeline* pipeline1 = createDummyPipeline();
    cmsPipeline* pipeline2 = createDummyPipeline();

    if (!pipeline1 || !pipeline2) {
        cmsPipelineFree(pipeline1);
        cmsPipelineFree(pipeline2);
        return 0;
    }

    // Test cmsPipelineDup
    cmsPipeline* dupPipeline = cmsPipelineDup(pipeline1);
    if (dupPipeline) {
        cmsPipelineFree(dupPipeline);
    }

    // Test cmsPipelineCat
    cmsPipelineCat(pipeline1, pipeline2);

    // Test cmsPipelineEval16
    cmsUInt16Number input[3] = { Data[0], Data[1 % Size], Data[2 % Size] };
    cmsUInt16Number output[3];
    cmsPipelineEval16(input, output, pipeline1);

    // Test cmsPipelineSetSaveAs8bitsFlag
    cmsBool oldFlag = cmsPipelineSetSaveAs8bitsFlag(pipeline1, Data[0] % 2);

    // Cleanup
    cmsPipelineFree(pipeline1);
    cmsPipelineFree(pipeline2);

    return 0;
}