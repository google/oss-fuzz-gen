#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

// Fuzzer entry point
int LLVMFuzzerTestOneInput_438(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for our needs
    if (size < 1) {
        return 0;
    }

    // Create a dummy cmsPipeline to hold the cmsStage
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 1, 1);
    if (pipeline == NULL) {
        return 0;
    }

    // Create a cmsStage object using a Little CMS function
    cmsStage *stage = cmsStageAllocIdentity(NULL, 1);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Add the stage to the pipeline
    if (!cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Call the function-under-test
    void *result = cmsStageData(stage);

    // Free the allocated pipeline (which also frees the stage)
    cmsPipelineFree(pipeline);

    // Return success
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

    LLVMFuzzerTestOneInput_438(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
