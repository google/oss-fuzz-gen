#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_349(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a non-NULL pointer
    if (size < sizeof(void *)) {
        return 0;
    }

    // Use the input data as a pointer
    void *pluginData = (void *)data;

    // Call the function-under-test
    cmsBool result = cmsPlugin(pluginData);

    // Use the result to prevent compiler optimizations
    if (result) {
        // Do something trivial
        volatile int dummy = 0;
        dummy++;
    }

    return 0;
}