#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    cmsPipeline *pipeline = NULL;
    cmsContext contextID;

    // Initialize a cmsPipeline structure with at least one stage to avoid NULL
    pipeline = cmsPipelineAlloc(NULL, 3, 3); // 3 input channels, 3 output channels
    if (pipeline == NULL) {
        return 0;
    }

    // Add a stage to the pipeline
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3); // Identity stage with 3 channels
    if (stage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage);
    }

    // Call the function-under-test
    contextID = cmsGetPipelineContextID(pipeline);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
