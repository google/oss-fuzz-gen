#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_288(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsIOHANDLER *ioHandler = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Initialize a memory-based IOHANDLER
    ioHandler = cmsOpenIOhandlerFromMem(context, (void *)data, (cmsUInt32Number)size, "r");
    if (ioHandler == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        cmsCloseIOhandler(ioHandler);
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function under test
    cmsUInt32Number result = cmsSaveProfileToIOhandler(hProfile, ioHandler);

    // Clean up
    cmsCloseIOhandler(ioHandler);
    cmsCloseProfile(hProfile);
    cmsDeleteContext(context);

    return 0;
}