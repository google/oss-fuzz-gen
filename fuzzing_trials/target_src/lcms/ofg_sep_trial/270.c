#include <stdint.h>
#include <lcms2.h>

// Define a sampler function separately as a regular function, not a lambda
int samplerFunc(const cmsFloat32Number In[], cmsFloat32Number Out[], void *Cargo) {
    for (int i = 0; i < 3; ++i) {
        Out[i] = In[i] * 2.0f; // Simple transformation for testing
    }
    return 1;
}

int LLVMFuzzerTestOneInput_270(const uint8_t *data, size_t size) {
    // Ensure size is large enough to extract necessary parameters
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize parameters for cmsStageAllocCLutFloat
    cmsUInt32Number nGridPoints = 3;
    cmsUInt32Number inputChan = 3;
    cmsUInt32Number outputChan = 3;
    cmsStage *stage = cmsStageAllocCLutFloat(NULL, nGridPoints, inputChan, outputChan, NULL);
    if (stage == NULL) {
        return 0;
    }

    void *cargo = NULL; // No additional data needed for this simple sampler function

    cmsUInt32Number nPoints = *(cmsUInt32Number *)data; // Use the first bytes of data as nPoints

    // Call the function-under-test
    cmsBool result = cmsStageSampleCLutFloat(stage, samplerFunc, cargo, nPoints);

    // Clean up
    cmsStageFree(stage);

    return 0;
}