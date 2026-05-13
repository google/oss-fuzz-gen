#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a profile from memory
    cmsHPROFILE profile = cmsOpenProfileFromMemTHR(context, data, size);

    // Check if the profile was created successfully
    if (profile != NULL) {
        // Call the function-under-test
        cmsProfileClassSignature deviceClass = cmsGetDeviceClass(profile);

        // Close the profile
        cmsCloseProfile(profile);
    }

    // Free the memory context
    cmsDeleteContext(context);

    return 0;
}