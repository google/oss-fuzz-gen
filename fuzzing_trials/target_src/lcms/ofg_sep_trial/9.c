#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number renderingIntent;

    // Check if size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract renderingIntent from the input data
    renderingIntent = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSetHeaderRenderingIntent(hProfile, renderingIntent);

    // Close the profile to avoid memory leaks
    cmsCloseProfile(hProfile);

    return 0;
}