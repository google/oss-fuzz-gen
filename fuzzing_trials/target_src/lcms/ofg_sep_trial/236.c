#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_236(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile;
    cmsFloat64Number gammaValue;
    cmsFloat64Number result;

    // Ensure size is sufficient to extract a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Create a profile from memory using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    gammaValue = *((cmsFloat64Number *)data);

    // Call the function-under-test
    result = cmsDetectRGBProfileGamma(hProfile, gammaValue);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}