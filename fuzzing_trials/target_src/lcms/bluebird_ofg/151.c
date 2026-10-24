#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3); // Allocate a pipeline with 3 inputs and 3 outputs
    cmsStageLoc loc = cmsAT_BEGIN; // Choose a location for the stage
    cmsToneCurve* toneCurves[3] = {NULL, NULL, NULL}; // Create an array for tone curves
    cmsStage *stage = cmsStageAllocToneCurves(NULL, 3, toneCurves); // Allocate a stage

    // Ensure the pipeline and stage are not NULL
    if (pipeline == NULL || stage == NULL) {
        return 0;
    }

    // Add the stage to the pipeline
    cmsPipelineInsertStage(pipeline, loc, stage);

    // Prepare a pointer to hold the unlinked stage
    cmsStage *unlinkedStage = NULL;

    // Call the function-under-test
    cmsPipelineUnlinkStage(pipeline, loc, &unlinkedStage);

    // Clean up
    if (unlinkedStage != NULL) {
        cmsStageFree(unlinkedStage);
    }
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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
