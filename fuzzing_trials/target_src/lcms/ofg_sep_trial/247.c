#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_247(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt64Number attributes;

    // Ensure the data size is sufficient to create a profile
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsGetHeaderAttributes(hProfile, &attributes);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}