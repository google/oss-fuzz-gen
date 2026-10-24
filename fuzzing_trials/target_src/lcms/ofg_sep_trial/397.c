#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Fuzzer entry point
int LLVMFuzzerTestOneInput_397(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a cmsPipeline
    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    // Initialize variables
    cmsUInt32Number inputChannels = *(const cmsUInt32Number *)data;
    cmsUInt32Number outputChannels = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    // Create a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, inputChannels, outputChannels);
    if (pipeline == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsPipelineOutputChannels(pipeline);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}