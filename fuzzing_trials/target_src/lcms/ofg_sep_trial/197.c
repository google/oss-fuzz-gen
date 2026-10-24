#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile;
    cmsUInt8Number profileID[16]; // Profile ID is typically 16 bytes

    // Create a memory-based profile using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0; // Return early if profile creation failed
    }

    // Call the function-under-test
    cmsGetHeaderProfileID(hProfile, profileID);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}