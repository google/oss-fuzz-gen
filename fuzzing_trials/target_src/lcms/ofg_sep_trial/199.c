#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext originalContext = cmsCreateContext(NULL, NULL);

    // Ensure the data is not NULL and has enough size
    if (size < sizeof(void*)) {
        cmsDeleteContext(originalContext);
        return 0;
    }

    // Use a portion of the data as a dummy void* argument
    void *clientData = (void *)data;

    // Call the function-under-test
    cmsContext duplicatedContext = cmsDupContext(originalContext, clientData);

    // Clean up
    cmsDeleteContext(originalContext);
    cmsDeleteContext(duplicatedContext);

    return 0;
}