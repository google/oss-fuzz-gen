#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Initialize the context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Call the function-under-test
    cmsHANDLE handle = cmsDictAlloc(context);

    // Clean up
    if (handle != NULL) {
        cmsDictFree(handle);
    }
    cmsDeleteContext(context);

    return 0;
}