#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_326(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;
    void *buffer = malloc(1024); // Allocate a buffer for the CSA
    cmsUInt32Number bufferSize = 1024;

    // Check if the profile was opened successfully
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsUInt32Number result = cmsGetPostScriptCSA(context, hProfile, intent, flags, buffer, bufferSize);

        // Clean up
        cmsCloseProfile(hProfile);
    }

    // Free allocated resources
    cmsDeleteContext(context);
    free(buffer);

    return 0;
}