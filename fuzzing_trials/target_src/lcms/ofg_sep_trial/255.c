#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_255(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsUInt32Number version;

    // Check if the size is sufficient to extract a version number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a version number from the data
    version = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSetEncodedICCversion(hProfile, version);

    // Close the profile after testing
    cmsCloseProfile(hProfile);

    return 0;
}