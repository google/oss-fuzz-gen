#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_322(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsHPROFILE profile;

    // Initialize the context
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure the data size is not zero before passing it to the function
    if (size == 0) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    profile = cmsOpenProfileFromMemTHR(context, (const void *)data, (cmsUInt32Number)size);

    // If a valid profile was opened, close it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}