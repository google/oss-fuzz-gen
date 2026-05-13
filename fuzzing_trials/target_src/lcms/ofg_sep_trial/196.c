#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt8Number profileID[16]; // Typically, profile IDs are 16 bytes long

    // Create a memory profile using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0; // Exit if the profile could not be created
    }

    // Call the function-under-test
    cmsGetHeaderProfileID(hProfile, profileID);

    // Close the profile after use
    cmsCloseProfile(hProfile);

    return 0;
}