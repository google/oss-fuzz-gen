#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_260(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromMemTHR(context, data, size);

    // Check if the profile was created successfully
    if (profile != NULL) {
        // Do something with the profile if needed
        // For fuzzing purposes, we can just close the profile
        cmsCloseProfile(profile);
    }

    // Free the context
    cmsDeleteContext(context);

    return 0;
}