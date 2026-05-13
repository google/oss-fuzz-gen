#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsBool result;

    // Ensure size is non-zero to create a valid profile from memory
    if (size == 0) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem((void *)data, (cmsUInt32Number)size);
    
    // If the profile creation fails, exit
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = cmsMD5computeID(hProfile);

    // Close the profile to free resources
    cmsCloseProfile(hProfile);

    return 0;
}