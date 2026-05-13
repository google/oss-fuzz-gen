#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_290(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number headerCreator;

    // Initialize the memory block for the profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem((void*)data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    headerCreator = cmsGetHeaderCreator(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}