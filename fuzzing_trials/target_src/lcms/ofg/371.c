#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_371(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Extract parameters from the input data
    cmsUInt32Number nGridPoints = *(const cmsUInt32Number *)data;
    cmsUInt32Number inputChannels = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));
    cmsUInt32Number outputChannels = *(const cmsUInt32Number *)(data + 2 * sizeof(cmsUInt32Number));

    // Calculate the number of float values required for the CLUT
    size_t numFloats = nGridPoints * inputChannels * outputChannels;
    
    // Ensure there is enough data for the float array
    if (size < 3 * sizeof(cmsUInt32Number) + numFloats * sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Pointer to the float array
    const cmsFloat32Number *floatArray = (const cmsFloat32Number *)(data + 3 * sizeof(cmsUInt32Number));

    // Create a dummy context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLutFloat(context, nGridPoints, inputChannels, outputChannels, floatArray);

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

    LLVMFuzzerTestOneInput_371(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
