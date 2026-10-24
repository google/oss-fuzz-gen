#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_449(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile;
    cmsTagSignature sig1, sig2;

    // Ensure size is sufficient for extracting tag signatures
    if (size < sizeof(cmsTagSignature) * 2) {
        return 0;
    }

    // Create a profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract tag signatures from the input data
    sig1 = *(cmsTagSignature *)(data);
    sig2 = *(cmsTagSignature *)(data + sizeof(cmsTagSignature));

    // Call the function under test
    cmsBool result = cmsLinkTag(hProfile, sig1, sig2);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}