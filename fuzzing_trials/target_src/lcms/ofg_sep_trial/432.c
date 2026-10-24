#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_432(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsPSResourceType resourceType = cmsPS_RESOURCE_CSA;
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = 0;  // Using 0 as a default rendering intent
    cmsUInt32Number flags = 0;   // Using 0 as default flags
    cmsIOHANDLER *iohandler = cmsOpenIOhandlerFromNULL(context);

    // Check if the profile was created successfully
    if (hProfile != NULL && iohandler != NULL) {
        // Call the function-under-test
        cmsUInt32Number result = cmsGetPostScriptColorResource(context, resourceType, hProfile, intent, flags, iohandler);

        // Clean up resources
        cmsCloseProfile(hProfile);
        cmsCloseIOhandler(iohandler);
    }

    cmsDeleteContext(context);

    return 0;
}