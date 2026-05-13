#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_478(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = 0; // Using 0 as a default intent
    cmsUInt32Number flags = 0; // Using 0 as a default flag
    void *buffer = malloc(size > 0 ? size : 1); // Allocate buffer, ensure non-NULL
    cmsUInt32Number bufferSize = size > 0 ? size : 1; // Ensure non-zero buffer size

    if (hProfile != NULL) {
        cmsGetPostScriptCRD(context, hProfile, intent, flags, buffer, bufferSize);
        cmsCloseProfile(hProfile);
    }

    free(buffer);
    cmsDeleteContext(context);

    return 0;
}