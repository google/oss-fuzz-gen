#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_336(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt64Number attributes;

    // Check if the size is sufficient to extract cmsUInt64Number
    if (size < sizeof(cmsUInt64Number)) {
        return 0;
    }

    // Initialize the attributes from the input data
    attributes = *((cmsUInt64Number*)data);

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsSetHeaderAttributes(hProfile, attributes);

    // Clean up the profile
    cmsCloseProfile(hProfile);

    return 0;
}