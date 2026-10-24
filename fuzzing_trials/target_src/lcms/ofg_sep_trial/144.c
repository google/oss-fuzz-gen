#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;
    cmsStage *stage = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    cmsUInt32Number inputChannels = *(const cmsUInt32Number *)data;
    cmsUInt32Number outputChannels = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    pipeline = cmsPipelineAlloc(context, inputChannels, outputChannels);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    stage = cmsStageAllocIdentity(context, inputChannels);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }

    if (!cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsPipelineInputChannels(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}