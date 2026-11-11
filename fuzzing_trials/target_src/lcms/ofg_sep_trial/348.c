#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_348(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a non-NULL pointer
    if (size < sizeof(void *)) {
        return 0;
    }

    // Use the data as a pointer to pass to cmsPlugin
    void *pluginData = (void *)data;

    // Call the function-under-test
    cmsBool result = cmsPlugin(pluginData);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result) {
        // Do something if cmsPlugin returns true
    }

    return 0;
}