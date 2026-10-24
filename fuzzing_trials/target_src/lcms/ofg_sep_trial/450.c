#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_450(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsHTRANSFORM)) {
        return 0;
    }

    // Create a transform using some default profiles and intents
    cmsHPROFILE hInProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE hOutProfile = cmsCreate_sRGBProfile();
    cmsHTRANSFORM transform = cmsCreateTransform(hInProfile, TYPE_RGB_8, hOutProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Call the function under test
    cmsDeleteTransform(transform);

    // Clean up
    cmsCloseProfile(hInProfile);
    cmsCloseProfile(hOutProfile);

    return 0;
}