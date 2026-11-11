#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Initialize a cmsContext object
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0; // Return if context creation fails
    }

    // Use the input data to create a profile
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);
    if (profile != NULL) {
        // Perform operations on the profile if needed
        cmsCloseProfile(profile);
    }

    // Clean up
    cmsDeleteContext(context);

    return 0;
}