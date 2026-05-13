#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsFloat64Number version;

    // Initialize the profile using a non-NULL value
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Ensure the data size is sufficient to extract a double
    if (size < sizeof(cmsFloat64Number)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    version = *((cmsFloat64Number *)data);

    // Call the function under test
    cmsSetProfileVersion(hProfile, version);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}