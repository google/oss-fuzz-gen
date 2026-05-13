#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_232(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to proceed
    if (size < 9) {
        return 0; // Not enough data to proceed
    }

    // Declare and initialize variables
    cmsPipeline *pipeline = cmsPipelineAlloc(NULL, 3, 3); // Assuming 3 input and 3 output channels
    cmsBool flag = (cmsBool)(data[0] % 2); // Use the first byte of data to set the flag

    // Check if pipeline allocation was successful
    if (pipeline == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsPipelineSetSaveAs8bitsFlag(pipeline, flag);

    // Additional operations to increase code coverage
    cmsStage *stage = cmsStageAllocToneCurves(NULL, 3, NULL);
    if (stage != NULL) {
        cmsPipelineInsertStage(pipeline, cmsAT_END, stage);
    }

    // Use more data to modify the pipeline
    if (size >= 9) {
        cmsFloat32Number input[3];
        input[0] = data[1] / 255.0f;
        input[1] = data[2] / 255.0f;
        input[2] = data[3] / 255.0f;

        cmsFloat32Number output[3];
        cmsPipelineEvalFloat(input, output, pipeline);
    }

    // Clean up
    cmsPipelineFree(pipeline);

    return 0;
}