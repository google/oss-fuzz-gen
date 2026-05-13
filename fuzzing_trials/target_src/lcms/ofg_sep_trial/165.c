#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Define the input and output arrays for cmsPipelineEval16
    cmsUInt16Number input[3] = {0, 0, 0};
    cmsUInt16Number output[3] = {0, 0, 0};

    // Ensure the size is sufficient to fill the input array
    if (size < sizeof(input)) {
        return 0;
    }

    // Copy data into the input array
    for (size_t i = 0; i < 3; i++) {
        input[i] = (cmsUInt16Number)((data[i * 2] << 8) | data[i * 2 + 1]);
    }

    // Create a dummy cmsPipeline object for testing
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (pipeline == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsPipelineEval16(input, output, pipeline);

    // Free the allocated pipeline
    cmsPipelineFree(pipeline);

    return 0;
}