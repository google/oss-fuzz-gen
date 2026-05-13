#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_357(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsPipeline *pipeline = NULL;

    // Create a pipeline with one stage to ensure we have a valid cmsStage
    pipeline = cmsPipelineAlloc(NULL, 0, 0);
    if (pipeline == NULL) {
        return 0;
    }

    // Add a placeholder stage to the pipeline
    stage = cmsStageAllocIdentity(NULL, 0);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Ensure that the data is large enough to copy into the stage's data
    cmsUInt32Number inputChannels = cmsStageInputChannels(stage);
    cmsUInt32Number outputChannels = cmsStageOutputChannels(stage);
    if (size < inputChannels * outputChannels * sizeof(cmsFloat32Number)) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Allocate memory for input and output data
    cmsFloat32Number *inputData = (cmsFloat32Number *)malloc(inputChannels * sizeof(cmsFloat32Number));
    cmsFloat32Number *outputData = (cmsFloat32Number *)malloc(outputChannels * sizeof(cmsFloat32Number));
    if (inputData == NULL || outputData == NULL) {
        free(inputData);
        free(outputData);
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Copy the input data into the inputData array
    memcpy(inputData, data, inputChannels * sizeof(cmsFloat32Number));

    // Call the function-under-test
    cmsPipelineEvalFloat(inputData, outputData, pipeline);

    // Cleanup
    free(inputData);
    free(outputData);
    cmsPipelineFree(pipeline);

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

    LLVMFuzzerTestOneInput_357(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
