#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_321(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsHPROFILE profile;

    // Initialize a context for the LCMS library
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0; // Return early if context creation fails
    }

    // Ensure the size is non-zero for valid profile creation
    if (size > 0) {
        // Call the function-under-test with the provided data
        profile = cmsOpenProfileFromMemTHR(context, (const void *)data, (cmsUInt32Number)size);

        // If a valid profile is returned, close it
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
    }

    // Free the context
    cmsDeleteContext(context);

    return 0;
}