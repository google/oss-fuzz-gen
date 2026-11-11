#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_324(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = (cmsContext)0x1; // Non-NULL context
    cmsUInt32Number inputChannels = 1;    // Minimum non-zero input channels
    cmsUInt32Number outputChannels = 1;   // Minimum non-zero output channels

    // Call the function-under-test
    cmsPipeline *pipeline = cmsPipelineAlloc(context, inputChannels, outputChannels);

    // Check if the allocation was successful
    if (pipeline != NULL) {
        // Free the allocated pipeline to avoid memory leaks
        cmsPipelineFree(pipeline);
    }

    return 0;
}