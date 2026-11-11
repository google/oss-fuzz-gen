#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_473(const uint8_t *data, size_t size) {
    cmsContext context = (cmsContext)(uintptr_t)data; // Cast data to cmsContext
    cmsUInt32Number num = (size > 0) ? (cmsUInt32Number)data[0] : 1; // Use first byte of data as cmsUInt32Number, default to 1 if size is 0

    // Call the function-under-test
    cmsMLU *mlu = cmsMLUalloc(context, num);

    // Clean up
    if (mlu != NULL) {
        cmsMLUfree(mlu);
    }

    return 0;
}