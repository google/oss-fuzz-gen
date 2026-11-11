#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsFloat64Number result;
    cmsFloat64Number inputNumber;

    // Ensure size is sufficient to extract a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize inputNumber from data
    inputNumber = *((cmsFloat64Number*)data);

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = cmsDetectRGBProfileGamma(hProfile, inputNumber);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}