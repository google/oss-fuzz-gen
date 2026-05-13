#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_462(const uint8_t *data, size_t size) {
    // Initialize the parameters for cmsWriteRawTag
    cmsHPROFILE hProfile;
    cmsTagSignature sig;
    const void *tagData;
    cmsUInt32Number tagSize;

    // Ensure size is large enough to extract necessary data
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract cmsTagSignature and cmsUInt32Number from data
    sig = *(cmsTagSignature *)data;
    tagSize = *(cmsUInt32Number *)(data + sizeof(cmsTagSignature));

    // Ensure tagSize does not exceed remaining data size
    if (tagSize > size - sizeof(cmsTagSignature) - sizeof(cmsUInt32Number)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Set tagData to point to the appropriate location in data
    tagData = (const void *)(data + sizeof(cmsTagSignature) + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsBool result = cmsWriteRawTag(hProfile, sig, tagData, tagSize);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}