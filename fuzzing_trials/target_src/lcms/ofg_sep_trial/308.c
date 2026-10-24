#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_308(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile;
    cmsTagSignature tagSig;
    const void *tagData;

    // Ensure size is sufficient to extract data
    if (size < sizeof(cmsTagSignature) + sizeof(void *)) {
        return 0;
    }

    // Create a dummy profile
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract tag signature from input data
    tagSig = *(cmsTagSignature *)data;

    // Extract tag data from input data
    tagData = (const void *)(data + sizeof(cmsTagSignature));

    // Call the function-under-test
    cmsBool result = cmsWriteTag(hProfile, tagSig, tagData);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}