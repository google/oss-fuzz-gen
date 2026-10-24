#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Initialize cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure there's at least enough data to create a non-NULL pointer
    if (size < sizeof(void *)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Use the data as a pointer
    void *pluginData = (void *)data;

    // Call the function-under-test
    cmsBool result = cmsPluginTHR(context, pluginData);

    // Clean up
    cmsDeleteContext(context);

    return 0;
}