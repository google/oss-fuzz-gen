#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract cmsUInt32Number from the input data
    cmsUInt32Number flags = *(const cmsUInt32Number *)data;

    // Call the function under test
    cmsSetHeaderFlags(hProfile, flags);

    // Close the profile to avoid memory leaks
    cmsCloseProfile(hProfile);

    return 0;
}