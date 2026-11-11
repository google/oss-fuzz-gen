#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number tagIndex;
    cmsTagSignature tagSignature;

    // Ensure there is enough data to extract the cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the profile from the data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the data
    tagIndex = *(const cmsUInt32Number*)data;

    // Call the function-under-test
    tagSignature = cmsGetTagSignature(hProfile, tagIndex);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}