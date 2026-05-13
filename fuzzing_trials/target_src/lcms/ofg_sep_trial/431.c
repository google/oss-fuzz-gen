#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_431(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsPSResourceType resourceType = cmsPS_RESOURCE_CSA;
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Create an IOHANDLER that does not perform actual I/O
    cmsIOHANDLER* ioHandler = cmsOpenIOhandlerFromNULL(context);

    if (hProfile != NULL && ioHandler != NULL) {
        cmsGetPostScriptColorResource(context, resourceType, hProfile, intent, flags, ioHandler);
        cmsCloseProfile(hProfile);
    }

    // Clean up
    if (ioHandler != NULL) {
        cmsCloseIOhandler(ioHandler);
    }
    cmsDeleteContext(context);

    return 0;
}