#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_392(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough for meaningful processing
    if (size < 1) {
        return 0;
    }

    // Create a cmsPipeline to hold the stage
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 1, 1);
    if (pipeline == NULL) {
        return 0;
    }

    // Create a cmsStage object using available API functions
    cmsStage *stage = cmsStageAllocIdentity(NULL, 1);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Add the stage to the pipeline
    cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage);

    // Call the function-under-test
    cmsStage *nextStage = cmsStageNext(stage);

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

    LLVMFuzzerTestOneInput_392(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
