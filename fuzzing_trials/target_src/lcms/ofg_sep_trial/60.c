#include <stdint.h>
#include "/src/lcms/include/lcms2.h"

// Define a valid cmsHPROFILE for testing purposes
cmsHPROFILE createTestProfile() {
    // Create a test profile with a dummy ICC profile
    cmsHPROFILE profile = cmsCreate_sRGBProfile();
    return profile;
}

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract a cmsColorSpaceSignature
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Create a test profile
    cmsHPROFILE hProfile = createTestProfile();

    // Extract a cmsColorSpaceSignature from the input data
    cmsColorSpaceSignature colorSpaceSignature = *(const cmsColorSpaceSignature *)data;

    // Call the function-under-test
    cmsSetPCS(hProfile, colorSpaceSignature);

    // Close the profile to avoid memory leaks
    cmsCloseProfile(hProfile);

    return 0;
}