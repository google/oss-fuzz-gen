#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_412(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for cmsStageAllocCLut16bit
    cmsContext context = (cmsContext)0x1; // Dummy non-null context
    cmsUInt32Number nGridPoints = 2; // A small but valid number of grid points
    cmsUInt32Number inputChannels = 3; // Common number of input channels (e.g., RGB)
    cmsUInt32Number outputChannels = 3; // Common number of output channels (e.g., RGB)

    // Ensure there is enough data to create the CLUT
    size_t requiredSize = nGridPoints * inputChannels * outputChannels * sizeof(cmsUInt16Number);
    if (size < requiredSize) {
        return 0; // Not enough data, exit early
    }

    // Cast the data to cmsUInt16Number pointer
    const cmsUInt16Number *clutTable = (const cmsUInt16Number *)data;

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLut16bit(context, nGridPoints, inputChannels, outputChannels, clutTable);

    // Clean up if the stage was allocated
    if (stage != NULL) {
        cmsStageFree(stage);
    }

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

    LLVMFuzzerTestOneInput_412(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
