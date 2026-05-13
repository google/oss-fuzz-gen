#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_465(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;

    // Check if the size is sufficient to create a profile
    if (size >= sizeof(cmsHPROFILE)) {
        // Create a profile from the input data
        hProfile = cmsOpenProfileFromMem(data, size);
    }

    if (hProfile != NULL) {
        // Call the function-under-test
        cmsColorSpaceSignature pcs = cmsGetPCS(hProfile);

        // Close the profile to avoid memory leaks
        cmsCloseProfile(hProfile);
    }

    return 0;
}