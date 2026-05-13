#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsUInt32Number nChannels;
    cmsStage *stage = NULL;

    // Initialize context and nChannels
    context = cmsCreateContext(NULL, NULL);
    nChannels = (size > 0) ? (cmsUInt32Number)(data[0] % 10 + 1) : 3; // Ensure nChannels is between 1 and 10

    // Call the function-under-test
    stage = cmsStageAllocIdentity(context, nChannels);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
    cmsDeleteContext(context);

    return 0;
}