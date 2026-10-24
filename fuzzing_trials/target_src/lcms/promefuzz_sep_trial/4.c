// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineInputChannels at cmslut.c:1413:27 in lcms2.h
// cmsPipelineOutputChannels at cmslut.c:1419:27 in lcms2.h
// cmsPipelineStageCount at cmslut.c:1661:27 in lcms2.h
// cmsPipelineCheckAndRetreiveStages at cmslut.c:110:20 in lcms2.h
// cmsPipelineAlloc at cmslut.c:1377:24 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "lcms2.h"

static void fuzz_cmsPipelineInputChannels(cmsPipeline* pipeline) {
    if (pipeline) {
        cmsUInt32Number inputChannels = cmsPipelineInputChannels(pipeline);
        printf("Input Channels: %u\n", inputChannels);
    }
}

static void fuzz_cmsPipelineOutputChannels(cmsPipeline* pipeline) {
    if (pipeline) {
        cmsUInt32Number outputChannels = cmsPipelineOutputChannels(pipeline);
        printf("Output Channels: %u\n", outputChannels);
    }
}

static void fuzz_cmsPipelineStageCount(cmsPipeline* pipeline) {
    if (pipeline) {
        cmsUInt32Number stageCount = cmsPipelineStageCount(pipeline);
        printf("Stage Count: %u\n", stageCount);
    }
}

static void fuzz_cmsPipelineCheckAndRetreiveStages(cmsPipeline* pipeline) {
    if (pipeline) {
        cmsStage* stages[10];
        cmsBool result = cmsPipelineCheckAndRetreiveStages(pipeline, 2, cmsSigCurveSetElemType, cmsSigMatrixElemType, &stages[0], &stages[1]);
        printf("Check and Retrieve Stages: %d\n", result);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    cmsContext context = NULL;
    cmsUInt32Number inputChannels = Data[0] % 10;
    cmsUInt32Number outputChannels = Data[1] % 10;

    cmsPipeline* pipeline = cmsPipelineAlloc(context, inputChannels, outputChannels);
    if (!pipeline) return 0;

    fuzz_cmsPipelineInputChannels(pipeline);
    fuzz_cmsPipelineOutputChannels(pipeline);
    fuzz_cmsPipelineStageCount(pipeline);
    fuzz_cmsPipelineCheckAndRetreiveStages(pipeline);

    cmsPipelineFree(pipeline);

    return 0;
}