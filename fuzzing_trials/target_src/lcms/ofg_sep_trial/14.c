#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;

    // Ensure size is sufficient to extract required variables
    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    // Initialize the profile
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract intent and flags from data
    intent = *(const cmsUInt32Number *)data;
    flags = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsBool result = cmsIsIntentSupported(hProfile, intent, flags);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}