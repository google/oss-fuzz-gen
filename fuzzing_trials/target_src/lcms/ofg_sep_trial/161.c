#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsUInt32Number renderingIntent;

    // Check if the size is sufficient for creating a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    renderingIntent = cmsGetHeaderRenderingIntent(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}