#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_242(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract necessary data
    if (size < sizeof(cmsBool)) {
        return 0;
    }

    // Initialize a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Extract cmsBool value from the input data
    cmsBool saveAs8bitsFlag = (cmsBool)(data[0] % 2); // Ensuring it's a boolean value

    // Call the function-under-test
    cmsBool result = cmsPipelineSetSaveAs8bitsFlag(pipeline, saveAs8bitsFlag);

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

    LLVMFuzzerTestOneInput_242(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
