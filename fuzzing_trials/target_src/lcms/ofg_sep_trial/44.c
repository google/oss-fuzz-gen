#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsUInt32Number model;

    // Ensure the data is not NULL and has a minimum size
    if (data == NULL || size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    model = cmsGetHeaderModel(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}