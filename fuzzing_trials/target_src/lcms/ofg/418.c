#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_418(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;
    cmsStage *stage = NULL;
    cmsContext context;
    cmsUInt32Number inputChannels = 3;
    cmsUInt32Number outputChannels = 3;

    // Create a memory context
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a pipeline
    pipeline = cmsPipelineAlloc(context, inputChannels, outputChannels);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add a dummy stage to the pipeline to ensure it's not empty
    cmsStage *dummyStage = cmsStageAllocIdentity(context, inputChannels);
    if (dummyStage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, dummyStage);
    }

    // Call the function-under-test
    stage = cmsPipelineGetPtrToFirstStage(pipeline);

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

    LLVMFuzzerTestOneInput_418(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
