#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create input and output arrays
    if (size < 4 * sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Initialize input and output arrays
    cmsUInt16Number input[4];
    cmsUInt16Number output[4];

    // Populate input array with data
    for (int i = 0; i < 4; i++) {
        input[i] = ((cmsUInt16Number *)data)[i];
    }

    // Create a dummy cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 4, 4);
    if (!pipeline) {
        return 0;
    }

    // Call the function-under-test
    cmsPipelineEval16(input, output, pipeline);

    // Free the cmsPipeline object
    cmsPipelineFree(pipeline);

    return 0;
}