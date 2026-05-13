#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsUInt32Number nInputsOutputs;

    // Initialize context and nInputsOutputs with non-NULL values
    context = cmsCreateContext(NULL, NULL);

    // Ensure size is sufficient to extract cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract cmsUInt32Number from data
    nInputsOutputs = *((cmsUInt32Number*)data);

    // Call the function with valid parameters
    cmsStage* stage = cmsStageAllocIdentity(context, nInputsOutputs);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
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

    LLVMFuzzerTestOneInput_106(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
