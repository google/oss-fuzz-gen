#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_295(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHANDLE handle = NULL;

    if (size > 0 && context != NULL) {
        // Call the function-under-test
        handle = cmsIT8LoadFromMem(context, (const void *)data, (cmsUInt32Number)size);

        // If handle is not NULL, free the resources
        if (handle != NULL) {
            cmsIT8Free(handle);
        }
    }

    // Free the context
    cmsDeleteContext(context);

    return 0;
}