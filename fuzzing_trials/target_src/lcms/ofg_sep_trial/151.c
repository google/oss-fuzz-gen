#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include string.h for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number adaptationState;
    memcpy(&adaptationState, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsFloat64Number result = cmsSetAdaptationState(adaptationState);

    // Use the result in some way to avoid compiler optimizations
    volatile cmsFloat64Number useResult = result;
    (void)useResult;

    return 0;
}