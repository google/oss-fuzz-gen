#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    if (size < 24) {
        return 0; // Ensure there's enough data for the CLUT table
    }
    
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number gridPoints[] = { 2, 2, 2 }; // Example grid points
    cmsUInt32Number inputChannels = 3; // Example number of input channels
    cmsUInt32Number outputChannels = 3; // Example number of output channels
    cmsFloat32Number clutTable[8 * 3]; // Adjusted size for CLUT table

    // Fill the CLUT table with data from the input
    for (size_t i = 0; i < 8 * 3; i++) {
        clutTable[i] = data[i % size] / 255.0f; // Normalize to 0.0f - 1.0f
    }

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLutFloatGranular(context, gridPoints, inputChannels, outputChannels, clutTable);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
    cmsDeleteContext(context);

    return 0;
}