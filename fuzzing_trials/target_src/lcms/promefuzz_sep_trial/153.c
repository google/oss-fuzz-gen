// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineAlloc at cmslut.c:1377:24 in lcms2.h
// cmsPipelineDup at cmslut.c:1464:24 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsPipelineEvalFloat at cmslut.c:1455:16 in lcms2.h
// cmsPipelineEvalReverseFloat at cmslut.c:1753:19 in lcms2.h
// cmsStageAllocIdentity at cmslut.c:70:21 in lcms2.h
// cmsPipelineInsertStage at cmslut.c:1519:15 in lcms2.h
// cmsPipelineSetSaveAs8bitsFlag at cmslut.c:1637:19 in lcms2.h
// cmsPipelineSetSaveAs8bitsFlag at cmslut.c:1637:19 in lcms2.h
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

static cmsPipeline* create_dummy_pipeline() {
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (!pipeline) return NULL;
    return pipeline;
}

int LLVMFuzzerTestOneInput_153(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat32Number) * 3) return 0;

    cmsPipeline* pipeline = create_dummy_pipeline();
    if (!pipeline) return 0;

    // Fuzz cmsPipelineDup
    cmsPipeline* dupPipeline = cmsPipelineDup(pipeline);
    if (dupPipeline) {
        cmsPipelineFree(dupPipeline);
    }

    // Fuzz cmsPipelineEvalFloat
    cmsFloat32Number input[3];
    cmsFloat32Number output[3];
    memcpy(input, Data, sizeof(cmsFloat32Number) * 3);
    cmsPipelineEvalFloat(input, output, pipeline);

    // Fuzz cmsPipelineEvalReverseFloat
    cmsFloat32Number result[3];
    cmsBool reverseSuccess = cmsPipelineEvalReverseFloat(output, result, NULL, pipeline);

    // Fuzz cmsPipelineInsertStage
    cmsStage* stage = cmsStageAllocIdentity(NULL, 3);
    if (stage) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage);
    }

    // Fuzz cmsPipelineSetSaveAs8bitsFlag
    cmsBool oldFlag = cmsPipelineSetSaveAs8bitsFlag(pipeline, TRUE);
    cmsPipelineSetSaveAs8bitsFlag(pipeline, oldFlag);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}