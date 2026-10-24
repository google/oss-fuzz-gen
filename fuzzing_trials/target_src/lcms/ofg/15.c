#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(cmsFloat32Number) * 2) {
        return 0;
    }

    // Initialize input and output arrays
    cmsFloat32Number input[1];
    cmsFloat32Number output[1];

    // Copy data into input array
    input[0] = *((cmsFloat32Number *)data);

    // Create a dummy pipeline for testing
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 1, 1);

    // Check if pipeline allocation was successful
    if (pipeline == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsPipelineEvalFloat(input, output, pipeline);

    // Free the pipeline
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

    LLVMFuzzerTestOneInput_15(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
