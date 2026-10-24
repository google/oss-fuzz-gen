#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_403(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cmsHPROFILE profile = cmsCreate_sRGBProfile();

    // Check if the profile was created successfully
    if (profile != NULL) {
        // Perform any additional operations if needed
        // ...

        // Close the profile to avoid memory leaks
        cmsCloseProfile(profile);
    }

    return 0;
}