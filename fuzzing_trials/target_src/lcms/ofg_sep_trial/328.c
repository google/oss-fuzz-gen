#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_328(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsUInt32Number version;

    // Create a profile from the input data if possible
    if (size > 0) {
        hProfile = cmsOpenProfileFromMem(data, size);
    }

    // If profile creation is successful, call the function
    if (hProfile != NULL) {
        version = cmsGetEncodedICCversion(hProfile);
        // Use the version in some way to avoid compiler optimizations
        (void)version;

        // Close the profile after use
        cmsCloseProfile(hProfile);
    }

    return 0;
}