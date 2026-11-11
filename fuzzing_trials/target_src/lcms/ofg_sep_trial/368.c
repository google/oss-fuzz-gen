#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_368(const uint8_t *data, size_t size) {
    void *userData = (void *)0x1; // Non-NULL dummy pointer for user data
    void *pluginData = (void *)0x2; // Non-NULL dummy pointer for plugin data

    // Call the function-under-test
    cmsContext context = cmsCreateContext(userData, pluginData);

    // Clean up the context if it was created successfully
    if (context != NULL) {
        cmsDeleteContext(context);
    }

    return 0;
}