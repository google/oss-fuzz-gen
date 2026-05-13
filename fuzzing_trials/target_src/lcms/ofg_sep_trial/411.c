#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_411(const uint8_t *data, size_t size) {
    // Declare and initialize variables for cmsIsTag
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsTagSignature tagSignature;

    // Check if the profile was opened successfully
    if (hProfile == NULL) {
        return 0;
    }

    // Ensure the size is large enough to extract a cmsTagSignature
    if (size < sizeof(cmsTagSignature)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract the cmsTagSignature from the input data
    tagSignature = *(cmsTagSignature*)data;

    // Call the function-under-test
    cmsBool result = cmsIsTag(hProfile, tagSignature);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}