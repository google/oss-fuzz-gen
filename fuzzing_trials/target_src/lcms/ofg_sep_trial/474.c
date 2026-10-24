#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsMLUalloc
int LLVMFuzzerTestOneInput_474(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = (cmsContext)0x1; // Using a non-NULL dummy context
    cmsUInt32Number num = 1; // Allocate at least one element

    // Call the function-under-test
    cmsMLU *mlu = cmsMLUalloc(context, num);

    // Clean up
    if (mlu != NULL) {
        cmsMLUfree(mlu);
    }

    return 0;
}