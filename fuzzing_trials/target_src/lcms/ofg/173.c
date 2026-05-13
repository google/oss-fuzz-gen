#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(cmsUInt16Number)) {
        return 0; // Not enough data to proceed
    }

    // Initialize input and output arrays
    cmsUInt16Number input[2];
    cmsUInt16Number output[2];

    // Populate input array with data
    input[0] = (cmsUInt16Number)data[0];
    input[1] = (cmsUInt16Number)data[1];

    // Create a dummy cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 2, 2);
    if (pipeline == NULL) {
        return 0; // Failed to allocate pipeline
    }

    // Call the function-under-test
    cmsPipelineEval16(input, output, pipeline);

    // Free the allocated pipeline
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

    LLVMFuzzerTestOneInput_173(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
