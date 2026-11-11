#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_437(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsBool result;

    // Check if the data size is sufficient to create a profile
    if (size > 0) {
        // Create a profile from the data
        hProfile = cmsOpenProfileFromMem(data, size);
    }

    // If the profile is successfully created, test the function
    if (hProfile != NULL) {
        result = cmsIsMatrixShaper(hProfile);
        // Close the profile after use
        cmsCloseProfile(hProfile);
    }

    return 0;
}