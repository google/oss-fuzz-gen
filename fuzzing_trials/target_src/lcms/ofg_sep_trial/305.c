#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_305(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateXYZProfile();

    // Perform operations on the profile if needed
    if (profile != NULL) {
        // For example, you can save the profile to memory or check its properties
        // Here, we'll just close the profile to ensure cleanup
        cmsCloseProfile(profile);
    }

    return 0;
}