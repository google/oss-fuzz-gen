#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_386(const uint8_t *data, size_t size) {
    // Initialize the variables
    cmsHTRANSFORM transform;

    // Create a dummy profile to create a transform
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Create a transform using the dummy profile
    transform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (transform == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call the function-under-test
    cmsContext contextID = cmsGetTransformContextID(transform);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(hProfile);

    return 0;
}