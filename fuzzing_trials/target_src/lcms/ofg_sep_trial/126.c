#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    cmsContext context = NULL;
    cmsHANDLE handle;

    // Initialize the context using the data provided
    if (size >= sizeof(cmsContext)) {
        context = (cmsContext)(uintptr_t)data; // Cast the data to a cmsContext for fuzzing
    } else {
        // If the size is insufficient, create a default context
        context = cmsCreateContext(NULL, NULL);
    }

    // Call the function-under-test
    handle = cmsGBDAlloc(context);

    // Clean up if necessary
    if (handle != NULL) {
        cmsGBDFree(handle);
    }

    if (context != NULL && size < sizeof(cmsContext)) {
        cmsDeleteContext(context);
    }

    return 0;
}