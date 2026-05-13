#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_283(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsInt32Number tagCount;
    
    // Ensure the input data is not NULL and has a valid size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Open a profile from memory using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    tagCount = cmsGetTagCount(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}