#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_313(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsPipeline *pipeline = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure the input size is sufficient for processing
    if (size < 3 * sizeof(float)) {
        return 0;
    }

    // Create a pipeline to hold the stage
    pipeline = cmsPipelineAlloc(context, 3, 3);
    if (!pipeline) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a stage from the input data
    stage = cmsStageAllocIdentity(context, 3);
    if (!stage) {
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }

    // Add the stage to the pipeline
    if (!cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number inputChannels = cmsStageInputChannels(stage);

    // Use the result in some way (e.g., print, log, etc.)
    // For the purpose of this harness, we simply ensure the function is called
    (void)inputChannels;  // Suppress unused variable warning

    // Clean up
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

    LLVMFuzzerTestOneInput_313(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
