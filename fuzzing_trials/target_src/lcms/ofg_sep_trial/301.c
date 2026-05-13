#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_301(const uint8_t *data, size_t size) {
    // Assume a reasonable minimum size for fuzzing purposes, e.g., 64 bytes
    const size_t minimumSize = 64;

    // Ensure the data size is sufficient
    if (size < minimumSize) {
        return 0;
    }

    // Cast the input data to a cmsStage pointer
    cmsStage *stage = (cmsStage *)data;

    // Call the function-under-test
    cmsUInt32Number inputChannels = cmsStageInputChannels(stage);

    // Use the result to prevent compiler optimizations
    volatile cmsUInt32Number result = inputChannels;
    (void)result;

    return 0;
}