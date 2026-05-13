#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Define a sampler function that matches the cmsSAMPLER16 type
cmsBool SamplerFunction(cmsUInt16Number In[], cmsUInt16Number Out[], void* Cargo) {
    // Simple sampler that copies input to output
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_206(const uint8_t *data, size_t size) {
    // Check if the input data is large enough to be meaningful
    if (size < 3 * sizeof(double)) {
        return 0;
    }

    // Initialize a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Add a stage to the pipeline to ensure it is not empty
    cmsStage *stage = cmsStageAllocIdentity(NULL, 3);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }
    cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage);

    // Fuzz the function-under-test
    cmsStage *lastStage = cmsPipelineGetPtrToLastStage(pipeline);
    if (lastStage != NULL) {
        // Use the input data to modify the stage or pipeline
        // For example, you could interpret the data as some parameters
        // Here, we just demonstrate by casting and using it
        double *params = (double *)data;
        (void)params; // Suppress unused variable warning

        // Call the function with the correct number of arguments
        cmsStageSampleCLut16bit(stage, SamplerFunction, NULL, 0);
    }

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

    LLVMFuzzerTestOneInput_206(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
