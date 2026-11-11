#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);

    // Check if the profile was created successfully
    if (profile != NULL) {
        // Perform operations on the profile if needed
        // ...

        // Close the profile to avoid memory leaks
        cmsCloseProfile(profile);
    }

    return 0;
}