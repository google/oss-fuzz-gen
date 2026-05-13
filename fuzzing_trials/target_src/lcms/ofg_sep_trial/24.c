#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Initialize variables for the function-under-test
    cmsHPROFILE hProfile;
    cmsFloat64Number version;

    // Create a dummy profile to ensure hProfile is not NULL
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Ensure size is sufficient to extract a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    version = *(const cmsFloat64Number *)data;

    // Call the function-under-test
    cmsSetProfileVersion(hProfile, version);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}