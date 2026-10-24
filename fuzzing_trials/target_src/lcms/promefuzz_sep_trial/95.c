// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineAlloc at cmslut.c:1377:24 in lcms2.h
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsMD5add at cmsmd5.c:172:16 in lcms2_plugin.h
// cmsPipelineInputChannels at cmslut.c:1413:27 in lcms2.h
// cmsPipelineCheckAndRetreiveStages at cmslut.c:110:20 in lcms2.h
// cmsPipelineEvalReverseFloat at cmslut.c:1753:19 in lcms2.h
// cmsPipelineOutputChannels at cmslut.c:1419:27 in lcms2.h
// cmsPipelineStageCount at cmslut.c:1661:27 in lcms2.h
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <lcms2_plugin.h>

typedef struct {
    cmsUInt32Number bits[2];
    cmsUInt32Number buf[4];
    unsigned char in[64];
} MD5Context;

static cmsHANDLE createMD5Context() {
    // Properly allocate memory for MD5Context
    MD5Context* ctx = (MD5Context*)malloc(sizeof(MD5Context));
    if (ctx) {
        memset(ctx, 0, sizeof(MD5Context)); // Initialize the context
    }
    return (cmsHANDLE)ctx;
}

static void destroyMD5Context(cmsHANDLE handle) {
    if (handle) {
        free(handle);
    }
}

static cmsPipeline* createDummyPipeline() {
    // Use cmsPipelineAlloc to create a dummy pipeline
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 3, 3);
    return pipeline;
}

static void destroyDummyPipeline(cmsPipeline* pipeline) {
    if (pipeline) {
        cmsPipelineFree(pipeline);
    }
}

int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Test cmsMD5add
    cmsHANDLE md5Handle = createMD5Context();
    if (md5Handle) {
        cmsMD5add(md5Handle, Data, (cmsUInt32Number)Size);
        destroyMD5Context(md5Handle);
    }

    // Test cmsPipelineInputChannels
    cmsPipeline* pipeline = createDummyPipeline();
    if (pipeline) {
        cmsUInt32Number inputChannels = cmsPipelineInputChannels(pipeline);

        // Test cmsPipelineCheckAndRetreiveStages
        cmsStage* stages[3];
        cmsBool stagesResult = cmsPipelineCheckAndRetreiveStages(pipeline, 3, stages);

        // Test cmsPipelineEvalReverseFloat
        cmsFloat32Number target[3] = {0.0f, 0.0f, 0.0f};
        cmsFloat32Number result[3];
        cmsFloat32Number hint[3] = {1.0f, 1.0f, 1.0f};
        cmsBool reverseResult = cmsPipelineEvalReverseFloat(target, result, hint, pipeline);

        // Test cmsPipelineOutputChannels
        cmsUInt32Number outputChannels = cmsPipelineOutputChannels(pipeline);

        // Test cmsPipelineStageCount
        cmsUInt32Number stageCount = cmsPipelineStageCount(pipeline);

        destroyDummyPipeline(pipeline);
    }

    return 0;
}