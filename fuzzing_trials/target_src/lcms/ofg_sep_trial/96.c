#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Check if the context was created successfully
    if (context == NULL) {
        return 0;
    }

    // Call the function-under-test with a valid context
    cmsUnregisterPluginsTHR(context);

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}