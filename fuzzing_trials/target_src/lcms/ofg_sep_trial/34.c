#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    cmsIOHANDLER *ioHandler;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Initialize the IOHANDLER with a memory block
    // Added "r" as the AccessMode to specify read access
    ioHandler = cmsOpenIOhandlerFromMem(context, (void *)data, size, "r");
    if (ioHandler == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsCloseIOhandler(ioHandler);

    // Clean up
    cmsDeleteContext(context);

    return 0;
}