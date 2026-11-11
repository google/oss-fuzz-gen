#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_256(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number version;

    // Ensure that the size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the input data
    version = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSetEncodedICCversion(hProfile, version);

    // Close the profile to free resources
    cmsCloseProfile(hProfile);

    return 0;
}