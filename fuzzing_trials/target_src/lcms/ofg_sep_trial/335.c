#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_335(const uint8_t *data, size_t size) {
    // Initialize cmsHPROFILE
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    
    // Ensure hProfile is valid
    if (hProfile == NULL) {
        return 0;
    }

    // Initialize cmsUInt64Number
    cmsUInt64Number attributes = 0;

    // Use the data to set some attributes, ensuring size is sufficient
    if (size >= sizeof(cmsUInt64Number)) {
        attributes = *((cmsUInt64Number*)data);
    }

    // Call the function under test
    cmsSetHeaderAttributes(hProfile, attributes);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}