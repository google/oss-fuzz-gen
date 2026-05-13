#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsUInt32Number model;

    // Check if the size is sufficient for cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a profile using cmsOpenProfileFromMem
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract cmsUInt32Number from data
    model = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSetHeaderModel(hProfile, model);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}