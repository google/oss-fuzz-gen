#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_220(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number gridPoints[] = { 2, 3, 4 }; // Example grid points
    cmsUInt32Number inputChannels = 3; // Example input channels
    cmsUInt32Number outputChannels = 3; // Example output channels

    // Ensure that the size is sufficient for the table data
    if (size < inputChannels * outputChannels * gridPoints[0] * gridPoints[1] * gridPoints[2] * sizeof(cmsUInt16Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    const cmsUInt16Number *table = (const cmsUInt16Number *)data;

    cmsStage *stage = cmsStageAllocCLut16bitGranular(context, gridPoints, inputChannels, outputChannels, table);

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

    LLVMFuzzerTestOneInput_220(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
