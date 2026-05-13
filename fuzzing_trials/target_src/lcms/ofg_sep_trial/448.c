#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_448(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsTagSignature) * 2) {
        return 0;
    }

    // Initialize the CMS profile
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract two tag signatures from the input data
    cmsTagSignature tag1 = *(const cmsTagSignature *)data;
    cmsTagSignature tag2 = *(const cmsTagSignature *)(data + sizeof(cmsTagSignature));

    // Call the function-under-test
    cmsBool result = cmsLinkTag(hProfile, tag1, tag2);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}