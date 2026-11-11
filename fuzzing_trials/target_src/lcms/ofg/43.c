#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(cmsStageLoc)) {
        return 0;
    }

    // Initialize the memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a pipeline
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);

    // Create a stage
    cmsStage *stage = cmsStageAllocIdentity(context, 3);

    // Extract cmsStageLoc from the input data
    cmsStageLoc stageLoc;
    memcpy(&stageLoc, data, sizeof(cmsStageLoc));

    // Call the function-under-test
    cmsBool result = cmsPipelineInsertStage(pipeline, stageLoc, stage);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsStageFree(stage);
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

    LLVMFuzzerTestOneInput_43(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
