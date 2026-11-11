#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsProfileClassSignature deviceClass;

    // Ensure size is sufficient to extract meaningful data
    if (size < sizeof(cmsProfileClassSignature)) {
        return 0;
    }

    // Initialize the profile using a dummy profile for fuzzing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsProfileClassSignature from the input data
    deviceClass = *(cmsProfileClassSignature *)data;

    // Call the function under test
    cmsSetDeviceClass(hProfile, deviceClass);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}