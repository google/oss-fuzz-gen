#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Initialize the cmsHPROFILE variable
    cmsHPROFILE hProfile;

    // Create a profile for testing purposes
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0; // Exit if profile creation fails
    }

    // Initialize cmsUInt32Number variable
    cmsUInt32Number flags = 0;

    // Ensure size is sufficient to extract a cmsUInt32Number from data
    if (size >= sizeof(cmsUInt32Number)) {
        // Extract cmsUInt32Number from data
        flags = *(const cmsUInt32Number *)data;
    }

    // Call the function-under-test
    cmsSetHeaderFlags(hProfile, flags);

    // Clean up by closing the profile
    cmsCloseProfile(hProfile);

    return 0;
}