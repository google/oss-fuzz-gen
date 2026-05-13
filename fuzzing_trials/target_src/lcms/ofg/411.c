#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_411(const uint8_t *data, size_t size) {
    // Ensure there's enough data for at least three cmsUInt32Number values
    if (size < 3 * sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract cmsUInt32Number values from the input data
    cmsUInt32Number nInputChannels = *(const cmsUInt32Number *)(data);
    cmsUInt32Number nOutputChannels = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));
    cmsUInt32Number gridPoints = *(const cmsUInt32Number *)(data + 2 * sizeof(cmsUInt32Number));

    // Ensure there's enough data for the LUT values
    size_t lutSize = nInputChannels * nOutputChannels * gridPoints * sizeof(cmsUInt16Number);
    if (size < 3 * sizeof(cmsUInt32Number) + lutSize) {
        return 0;
    }

    const cmsUInt16Number *lutTable = (const cmsUInt16Number *)(data + 3 * sizeof(cmsUInt32Number));

    // Create a dummy context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLut16bit(context, nInputChannels, nOutputChannels, gridPoints, lutTable);

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

    LLVMFuzzerTestOneInput_411(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
