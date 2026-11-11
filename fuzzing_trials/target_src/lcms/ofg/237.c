#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    cmsFloat32Number input[3] = {0.0f, 0.0f, 0.0f};
    cmsFloat32Number output[3] = {0.0f, 0.0f, 0.0f};
    cmsFloat32Number hint[3] = {0.0f, 0.0f, 0.0f};
    
    // Initialize a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (!pipeline) {
        return 0;
    }

    // Ensure the data size is sufficient to fill the input array
    if (size >= sizeof(input)) {
        for (size_t i = 0; i < 3; i++) {
            input[i] = ((cmsFloat32Number *)data)[i];
        }
    }

    // Call the function-under-test
    cmsBool result = cmsPipelineEvalReverseFloat(output, input, hint, pipeline);

    // Free the cmsPipeline object
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

    LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
