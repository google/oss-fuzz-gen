#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_289(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsIOHANDLER *ioHandler;
    cmsContext contextID = NULL; // Default context

    // Create a profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Create a memory IO handler
    // Allocate a buffer with the same size as the input data
    void *buffer = malloc(size);
    if (buffer == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Use "w" as the access mode to allow writing
    ioHandler = cmsOpenIOhandlerFromMem(contextID, buffer, size, "w");
    if (ioHandler == NULL) {
        free(buffer);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsSaveProfileToIOhandler(hProfile, ioHandler);

    // Clean up
    cmsCloseIOhandler(ioHandler);
    free(buffer);
    cmsCloseProfile(hProfile);

    return 0;
}