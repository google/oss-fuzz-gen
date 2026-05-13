#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_321(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3); // Allocate a pipeline with 3 input and 3 output channels

    if (pipeline == NULL) {
        return 0; // If allocation fails, exit early
    }

    // Simulate some operations on the pipeline using the input data
    // For example, add some stages to the pipeline if the data size is sufficient
    if (size > 0) {
        cmsStage *stage = cmsStageAllocIdentity(NULL, 3); // Create an identity stage
        if (stage != NULL) {
            cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage);
        }
    }

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_321(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
