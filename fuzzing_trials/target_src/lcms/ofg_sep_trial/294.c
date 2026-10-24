#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_294(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHANDLE handle;

    if (context == NULL || data == NULL || size == 0) {
        return 0;
    }

    handle = cmsIT8LoadFromMem(context, (const void *)data, (cmsUInt32Number)size);

    if (handle != NULL) {
        cmsIT8Free(handle);
    }

    cmsDeleteContext(context);

    return 0;
}