#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_262(const uint8_t *data, size_t size) {
    if (size < sizeof(float) * 3) {
        // Not enough data to create a stage, exit early
        return 0;
    }

    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Ensure that the pipeline is not empty by adding an identity stage
    cmsStage *stage = cmsStageAllocIdentity(context, 3);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        cmsDeleteContext(context);
        return 0;
    }
    cmsPipelineInsertStage(pipeline, cmsAT_END, stage);

    // Use the input data to create a new stage and add it to the pipeline
    // Assume the input data represents a matrix for a matrix stage
    cmsStage *matrixStage = cmsStageAllocMatrix(context, 3, 3, (const double *)data, NULL);
    if (matrixStage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, matrixStage);
    }

    // Duplicate the pipeline using the function-under-test
    cmsPipeline *dupPipeline = cmsPipelineDup(pipeline);

    // Clean up
    if (dupPipeline != NULL) {
        cmsPipelineFree(dupPipeline);
    }
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

    LLVMFuzzerTestOneInput_262(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
