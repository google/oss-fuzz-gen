#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_475(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Extract cmsUInt32Number from the input data
    cmsUInt32Number number = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSEQ *seq = cmsAllocProfileSequenceDescription(context, number);

    // Clean up
    if (seq != NULL) {
        cmsFreeProfileSequenceDescription(seq);
    }

    cmsDeleteContext(context);

    return 0;
}