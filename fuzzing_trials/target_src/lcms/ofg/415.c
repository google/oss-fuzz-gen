#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_415(const uint8_t *data, size_t size) {
    // Initialize memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create two cmsPipeline objects
    cmsPipeline *dest = cmsPipelineAlloc(context, 3, 3);
    cmsPipeline *src = cmsPipelineAlloc(context, 3, 3);

    // Ensure both pipelines are not NULL
    if (dest == NULL || src == NULL) {
        if (dest != NULL) cmsPipelineFree(dest);
        if (src != NULL) cmsPipelineFree(src);
        cmsDeleteContext(context);
        return 0;
    }

    // Add a dummy stage to the source pipeline to ensure it is not empty
    cmsStage *stage = cmsStageAllocIdentity(context, 3);
    if (stage != NULL) {
        cmsPipelineInsertStage(src, cmsAT_END, stage);
    }

    // Call the function-under-test
    cmsBool result = cmsPipelineCat(dest, src);

    // Clean up
    cmsPipelineFree(dest);
    cmsPipelineFree(src);
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

    LLVMFuzzerTestOneInput_415(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
