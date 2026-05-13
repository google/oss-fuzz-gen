#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_248(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt64Number attributes = 0;

    // Create a memory-based profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;  // If the profile cannot be opened, exit early
    }

    // Call the function under test
    cmsGetHeaderAttributes(hProfile, &attributes);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}