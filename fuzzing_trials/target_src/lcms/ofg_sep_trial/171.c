#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    cmsHANDLE handle = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (context != NULL) {
        handle = cmsIT8Alloc(context);
        if (handle != NULL) {
            // Example operation: use the input data if possible
            if (size > 0) {
                double sampleValue = (double)data[0] / 255.0; // Normalize first byte to a double
                cmsIT8SetPropertyDbl(handle, "SAMPLE", sampleValue);
            }
            cmsIT8Free(handle);
        }
        cmsDeleteContext(context);
    }

    return 0;
}