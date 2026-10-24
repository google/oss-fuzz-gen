#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_479(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = 0; // Use a simple value for intent
    cmsUInt32Number flags = 0;  // Use a simple value for flags
    void *buffer = malloc(1024); // Allocate a buffer
    cmsUInt32Number bufferSize = 1024; // Define the buffer size

    // Check if the profile was opened successfully
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsUInt32Number result = cmsGetPostScriptCRD(context, hProfile, intent, flags, buffer, bufferSize);

        // Cleanup
        cmsCloseProfile(hProfile);
    }

    // Free the allocated buffer
    free(buffer);

    // Cleanup the context
    cmsDeleteContext(context);

    return 0;
}