#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_323(const uint8_t *data, size_t size) {
    // Ensure there is enough data to cast to a cmsContext
    if (size < sizeof(uintptr_t)) {
        return 0;
    }

    // Declare and initialize variables
    cmsContext context = (cmsContext)(uintptr_t)data;  // Casting data to cmsContext
    cmsUInt32Number inputChannels = 3;  // Example value for input channels
    cmsUInt32Number outputChannels = 3; // Example value for output channels

    // Call the function-under-test
    cmsPipeline *pipeline = cmsPipelineAlloc(context, inputChannels, outputChannels);

    // Check if the pipeline was successfully allocated
    if (pipeline != NULL) {
        // Do something with the pipeline if needed
        // ...

        // Free the allocated pipeline
        cmsPipelineFree(pipeline);
    }

    return 0;
}