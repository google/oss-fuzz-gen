#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;

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
    cmsUInt32Number renderingIntent = cmsGetHeaderRenderingIntent(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}