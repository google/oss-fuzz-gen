#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for our operations
    if (size < 3 * sizeof(float)) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3); // Allocate a pipeline with 3 input and 3 output channels
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3); // Allocate an identity stage with 3 channels

    // Ensure that pipeline and stage are not NULL
    if (pipeline == NULL || stage == NULL) {
        if (pipeline != NULL) cmsPipelineFree(pipeline);
        if (stage != NULL) cmsStageFree(stage);
        return 0;
    }

    // Add the stage to the pipeline
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Prepare input data for the pipeline
    float input[3];
    for (int i = 0; i < 3; i++) {
        input[i] = ((float*)data)[i]; // Use the fuzzer data as input
    }

    // Output buffer
    float output[3];

    // Call the function-under-test
    cmsPipelineEvalFloat(input, output, pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    // Remove the call to cmsStageFree(stage) since the stage is managed by the pipeline and will be freed with it

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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
