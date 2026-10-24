#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_258(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the test
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the memory context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a cmsPipeline object
    cmsPipeline *pipeline = cmsPipelineAlloc(context, 3, 3);
    if (pipeline == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract a cmsUInt32Number from the data
    cmsUInt32Number n = *(cmsUInt32Number *)data;

    // Call the function-under-test
    cmsBool result = cmsPipelineCheckAndRetreiveStages(pipeline, n, NULL);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsDeleteContext(context);

    return 0;
}