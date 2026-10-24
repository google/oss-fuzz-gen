#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_352(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nGridPoints = 2; // A small number for simplicity
    cmsUInt32Number inputChannels = 3; // Typical for RGB
    cmsUInt32Number outputChannels = 3; // Typical for RGB

    // Ensure the size is sufficient for the LUT data
    if (size < nGridPoints * inputChannels * outputChannels * sizeof(cmsFloat32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Cast the input data to cmsFloat32Number array
    const cmsFloat32Number *lutTable = (const cmsFloat32Number *)data;

    // Call the function under test
    cmsStage *stage = cmsStageAllocCLutFloat(context, nGridPoints, inputChannels, outputChannels, lutTable);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
    cmsDeleteContext(context);

    return 0;
}