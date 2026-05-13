#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsFloat64Number adaptationState;
    // Copy bytes from data to the adaptationState variable
    memcpy(&adaptationState, data, sizeof(cmsFloat64Number));

    // Call the function-under-test with the adaptationState
    cmsFloat64Number result = cmsSetAdaptationState(adaptationState);

    // Use the result in some way to prevent compiler optimizations from removing the call
    volatile cmsFloat64Number useResult = result;
    (void)useResult;

    return 0;
}