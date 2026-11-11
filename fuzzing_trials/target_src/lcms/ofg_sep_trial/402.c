#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_402(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cmsHPROFILE profile = cmsCreate_sRGBProfile();

    // Perform a simple operation to ensure the profile is valid
    if (profile != NULL) {
        // Use the profile in some way, for example, check its class
        cmsProfileClassSignature profileClass = cmsGetDeviceClass(profile);

        // Clean up by closing the profile
        cmsCloseProfile(profile);
    }

    return 0;
}