#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"
#include <stdlib.h> // Include the standard library for malloc and free

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract necessary parameters
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Initialize parameters for cmsStageAllocCLutFloatGranular
    cmsContext context = (cmsContext)0x1; // Dummy non-NULL context
    cmsUInt32Number gridPoints[3] = {2, 2, 2}; // Example grid points for a 3D CLUT
    cmsUInt32Number inputChannels = 3; // Example input channels
    cmsUInt32Number outputChannels = 3; // Example output channels

    // Allocate memory for float data
    size_t numElements = gridPoints[0] * gridPoints[1] * gridPoints[2] * outputChannels;
    cmsFloat32Number *floatData = (cmsFloat32Number *)malloc(numElements * sizeof(cmsFloat32Number));

    if (floatData == NULL) {
        return 0;
    }

    // Fill floatData with values from the input data
    for (size_t i = 0; i < numElements; i++) {
        if (i < size / sizeof(cmsFloat32Number)) {
            floatData[i] = ((const cmsFloat32Number *)data)[i];
        } else {
            floatData[i] = 0.0f; // Default value if data is insufficient
        }
    }

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLutFloatGranular(context, gridPoints, inputChannels, outputChannels, floatData);

    // Free allocated memory
    free(floatData);

    // Check if stage is not NULL and free it if necessary
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
