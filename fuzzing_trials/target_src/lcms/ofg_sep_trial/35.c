#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure we have enough data to create a valid IO handler
    if (size == 0) {
        return 0;
    }

    // Create an IO handler using a function provided by Little CMS
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsIOHANDLER *handler = cmsOpenIOhandlerFromMem(context, (void *)data, size, "r");
    if (!handler) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsCloseIOhandler(handler);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result) {
        // Do something if needed
    }

    // Free the handler and context
    cmsDeleteContext(context);

    return 0;
}