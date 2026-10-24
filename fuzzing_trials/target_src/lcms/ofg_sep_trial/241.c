#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_241(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number inputChannels = 3;  // Example value, can be varied
    cmsUInt32Number outputChannels = 3; // Example value, can be varied

    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIsCLUT(hProfile, inputChannels, outputChannels);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}