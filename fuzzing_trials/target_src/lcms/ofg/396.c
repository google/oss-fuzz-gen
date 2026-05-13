#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsPipelineStageCount
int LLVMFuzzerTestOneInput_396(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a pipeline with a specific number of stages
    pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add some stages to the pipeline
    cmsStage *stage1 = cmsStageAllocIdentity(context, 3);
    cmsStage *stage2 = cmsStageAllocIdentity(context, 3);
    cmsStage *stage3 = cmsStageAllocIdentity(context, 3);

    if (stage1 && stage2 && stage3) {
        cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage1);
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage2);
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage3);
    }

    // Call the function-under-test
    cmsUInt32Number stageCount = cmsPipelineStageCount(pipeline);

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

    LLVMFuzzerTestOneInput_396(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
