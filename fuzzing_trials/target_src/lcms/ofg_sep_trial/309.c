#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_309(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsTagSignature) + sizeof(uint32_t)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile;
    cmsTagSignature tagSignature;
    const void *tagData;

    // Create a profile for fuzzing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract tagSignature from the data
    tagSignature = *(cmsTagSignature *)data;
    data += sizeof(cmsTagSignature);
    size -= sizeof(cmsTagSignature);

    // Use the remaining data as the tag data
    tagData = (const void *)data;

    // Call the function-under-test
    cmsWriteTag(hProfile, tagSignature, tagData);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}