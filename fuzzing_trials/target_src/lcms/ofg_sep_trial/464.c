#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_464(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a memory block for the profile
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsColorSpaceSignature pcs = cmsGetPCS(hProfile);

    // Clean up the profile
    cmsCloseProfile(hProfile);

    return 0;
}