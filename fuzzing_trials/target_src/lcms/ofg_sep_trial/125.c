#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (context == NULL) {
        return 0; // Early return if context creation fails
    }

    // Call the function-under-test
    cmsHANDLE handle = cmsGBDAlloc(context);

    if (handle != NULL) {
        // Use the handle in some way if needed, or just ensure it was allocated
        // For example, we could perform some operations on the handle here
        // but since this is a fuzzing harness, the main goal is to test allocation
    }

    // Clean up
    cmsDeleteContext(context);

    return 0;
}