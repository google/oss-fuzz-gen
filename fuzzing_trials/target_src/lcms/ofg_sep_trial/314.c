#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_314(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt8Number profileID[16]; // Profile ID is typically 16 bytes

    // Initialize the profile with a dummy profile
    hProfile = cmsCreate_sRGBProfile();

    // Ensure the data size is sufficient to fill the profileID
    if (size >= sizeof(profileID)) {
        // Copy data into profileID
        for (size_t i = 0; i < sizeof(profileID); i++) {
            profileID[i] = data[i];
        }

        // Call the function under test
        cmsSetHeaderProfileID(hProfile, profileID);
    }

    // Close the profile to avoid memory leaks
    cmsCloseProfile(hProfile);

    return 0;
}