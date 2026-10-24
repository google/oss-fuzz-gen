#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number Intent;
    cmsUInt32Number Direction;
    cmsBool result;

    // Ensure size is sufficient to extract necessary parameters
    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    // Create a profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract Intent and Direction from the data
    Intent = *((cmsUInt32Number*)data);
    Direction = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number)));

    // Call the function-under-test
    result = cmsIsCLUT(hProfile, Intent, Direction);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}