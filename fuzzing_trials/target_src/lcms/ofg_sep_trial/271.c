#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Define the sampler function outside of LLVMFuzzerTestOneInput
int sampler(const cmsFloat32Number In[], cmsFloat32Number Out[], void *Cargo) {
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return 1;
}

int LLVMFuzzerTestOneInput_271(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the CMS stage with the correct number of arguments
    cmsUInt32Number nGridPoints = 3; // Example value
    cmsUInt32Number inputChan = 3;
    cmsUInt32Number outputChan = 3;
    cmsStage *stage = cmsStageAllocCLutFloat(NULL, nGridPoints, inputChan, outputChan, NULL);
    if (stage == NULL) {
        return 0;
    }

    // Allocate some memory for the Cargo parameter
    void *cargo = malloc(1); // Just a dummy allocation

    // Extract a cmsUInt32Number from the input data
    cmsUInt32Number n = *(cmsUInt32Number *)data;

    // Call the function-under-test
    cmsBool result = cmsStageSampleCLutFloat(stage, sampler, cargo, n);

    // Clean up
    cmsStageFree(stage);
    free(cargo);

    return 0;
}