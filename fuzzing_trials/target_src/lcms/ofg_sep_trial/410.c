#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_410(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsTagSignature tagSignature;
    void *result;

    // Ensure that the input size is sufficient for our needs
    if (size < sizeof(cmsTagSignature)) {
        return 0;
    }

    // Create a memory-based profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a tag signature from the input data
    tagSignature = *(cmsTagSignature *)data;

    // Call the function-under-test
    result = cmsReadTag(hProfile, tagSignature);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}