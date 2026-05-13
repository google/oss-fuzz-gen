#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_304(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateXYZProfile();

    // Check if the profile was created successfully
    if (profile != NULL) {
        // Normally, you would perform additional operations on the profile here,
        // such as using it in a color transformation, but for the purpose of this
        // fuzzing harness, we simply release the profile.
        cmsCloseProfile(profile);
    }

    return 0;
}