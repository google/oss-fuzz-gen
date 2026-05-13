#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsFloat64Number result;

    // Ensure the data is large enough to be a valid profile
    if (size < 128) {
        return 0;
    }

    // Create a memory-based profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = cmsDetectTAC(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}