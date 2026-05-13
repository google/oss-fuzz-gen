#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_325(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = 0; // Rendering intent, can be varied
    cmsUInt32Number flags = 0;  // Flags, can be varied
    cmsUInt32Number bufferSize = 1024; // Arbitrary buffer size
    void *buffer = malloc(bufferSize);

    // Ensure profile and buffer are not NULL
    if (profile != NULL && buffer != NULL) {
        // Call the function under test
        cmsUInt32Number result = cmsGetPostScriptCSA(context, profile, intent, flags, buffer, bufferSize);

        // Use the result in some way to avoid compiler optimizations (optional)
        (void)result;
    }

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    if (buffer != NULL) {
        free(buffer);
    }
    cmsDeleteContext(context);

    return 0;
}