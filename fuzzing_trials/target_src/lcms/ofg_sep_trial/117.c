#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for cmsSetDeviceClass
    cmsHPROFILE profile;
    cmsProfileClassSignature deviceClass;

    // Initialize the profile using cmsOpenProfileFromMem
    if (size < sizeof(cmsProfileClassSignature)) {
        return 0; // Ensure there's enough data to proceed
    }

    // Open a profile from the provided data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0; // If profile creation fails, exit
    }

    // Extract a cmsProfileClassSignature from the data
    deviceClass = *(cmsProfileClassSignature *)data;

    // Call the function-under-test
    cmsSetDeviceClass(profile, deviceClass);

    // Close the profile to avoid memory leaks
    cmsCloseProfile(profile);

    return 0;
}