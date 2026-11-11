#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least one input and one output value
    if (size < 4) {
        return 0;
    }
    
    // Allocate memory for input and output
    cmsUInt16Number input[1];
    cmsUInt16Number output[1];

    // Initialize input from the data
    input[0] = (cmsUInt16Number)((data[0] << 8) | data[1]);
    
    // Create a dummy cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 1, 1);
    if (pipeline == NULL) {
        return 0;
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

    LLVMFuzzerTestOneInput_172(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
