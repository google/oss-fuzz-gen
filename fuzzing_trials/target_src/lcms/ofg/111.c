#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Define a sample sampler function
static cmsBool sampleSamplerFunction(register const cmsUInt16Number In[],
                                     register cmsUInt16Number Out[],
                                     register void * Cargo) {
    // Simple sampler function that copies input to output
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsPipeline *pipeline = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number gridPoints = 2;  // Arbitrary non-zero value

    // Create a pipeline with one stage
    pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline == NULL) {
        goto cleanup;
    }

    stage = cmsStageAllocCLut16bitGranular(context, gridPoints, 3, 3, NULL);
    if (stage == NULL) {
        goto cleanup;
    }

    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Call the function-under-test
    cmsStageSampleCLut16bit(stage, sampleSamplerFunction, NULL, gridPoints);

cleanup:
    if (pipeline != NULL) {
        cmsPipelineFree(pipeline);
    }
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

    LLVMFuzzerTestOneInput_111(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
