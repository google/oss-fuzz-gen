#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_233(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3);
    cmsBool flag = (cmsBool)(data[0] % 2); // Use the first byte of data to set the flag

    // Ensure the pipeline is not NULL
    if (pipeline == NULL) {
        return 0;
    }

    // Call the function under test
    cmsBool result = cmsPipelineSetSaveAs8bitsFlag(pipeline, flag);

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}