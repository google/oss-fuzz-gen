#include <stdint.h>
#include <stddef.h>
#include "/src/lcms/include/lcms2.h"

int LLVMFuzzerTestOneInput_356(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsPipeline *pipeline = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsTagTypeSignature stageType;
    size_t dataSize;
    const uint8_t *stageData;
    cmsUInt32Number outputChannels;

    if (size < sizeof(cmsTagTypeSignature)) {
        return 0;
    }

    // Create a dummy stage using the provided data
    stageType = *(cmsTagTypeSignature *)data;
    dataSize = size - sizeof(cmsTagTypeSignature);
    stageData = data + sizeof(cmsTagTypeSignature);

    // Create a pipeline and add a stage to it
    pipeline = cmsPipelineAlloc(context, 1, 1);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate a stage using a valid cmsStage allocation function
    cmsToneCurve* curve = cmsBuildGamma(context, 2.2); // Example gamma curve
    stage = cmsStageAllocToneCurves(context, 1, &curve);
    cmsFreeToneCurve(curve);

    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }

    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Call the function-under-test
    outputChannels = cmsStageOutputChannels(stage);

    // Use the outputChannels variable to avoid unused variable warning
    (void)outputChannels;

    // Cleanup
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_356(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
