#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number gridPoints[3] = {2, 2, 2};  // Example grid points for a 3D CLUT
    cmsUInt32Number inputChannels = 3;  // Example number of input channels
    cmsUInt32Number outputChannels = 3; // Example number of output channels

    // Allocate memory for CLUT data, ensuring it's not NULL
    cmsFloat32Number *clutData = (cmsFloat32Number *)malloc(sizeof(cmsFloat32Number) * gridPoints[0] * gridPoints[1] * gridPoints[2] * outputChannels);
    if (clutData == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize CLUT data with some values, avoiding NULL
    for (size_t i = 0; i < gridPoints[0] * gridPoints[1] * gridPoints[2] * outputChannels; i++) {
        clutData[i] = (cmsFloat32Number)(i % 256) / 255.0f;  // Example initialization
    }

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLutFloatGranular(context, gridPoints, inputChannels, outputChannels, clutData);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
    free(clutData);
    cmsDeleteContext(context);

    return 0;
}