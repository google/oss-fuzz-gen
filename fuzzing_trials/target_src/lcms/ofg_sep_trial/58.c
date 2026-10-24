#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number model;

    // Ensure the input size is sufficient for extracting cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a profile to use for fuzzing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the input data
    model = *(const cmsUInt32Number *)data;

    // Call the function under test
    cmsSetHeaderModel(hProfile, model);

    // Close the profile after use
    cmsCloseProfile(hProfile);

    return 0;
}