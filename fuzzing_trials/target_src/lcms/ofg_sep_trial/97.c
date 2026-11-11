#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Initialize the context with a non-NULL value
    cmsContext context = cmsCreateContext(NULL, NULL);
    
    // Call the function-under-test
    cmsUnregisterPluginsTHR(context);

    // Clean up
    cmsDeleteContext(context);

    return 0;
}