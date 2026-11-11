#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_205(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;
    cmsStage *lastStage = NULL;

    // Ensure that the size is sufficient to proceed with meaningful operations
    if (size < 3 * sizeof(float)) {
        return 0;
    }

    // Create a dummy pipeline for testing
    pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Add some stages to the pipeline to ensure it is not empty
    cmsStage *stage1 = cmsStageAllocIdentity(NULL, 3);
    cmsStage *stage2 = cmsStageAllocIdentity(NULL, 3);
    cmsStage *stage3 = cmsStageAllocIdentity(NULL, 3);

    if (stage1 && stage2 && stage3) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage1);
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage2);
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage3);
    }

    // Call the function-under-test
    lastStage = cmsPipelineGetPtrToLastStage(pipeline);

    // Clean up
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

    LLVMFuzzerTestOneInput_205(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
