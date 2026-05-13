#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsPipelineFree
int LLVMFuzzerTestOneInput_320(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create a cmsPipeline
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);

    // Ensure that the pipeline is not NULL
    if (pipeline == NULL) {
        return 0;
    }

    // Create a dummy stage to add to the pipeline
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Add the stage to the pipeline
    if (!cmsPipelineInsertStage(pipeline, cmsAT_END, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Call the function under test
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

    LLVMFuzzerTestOneInput_320(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
