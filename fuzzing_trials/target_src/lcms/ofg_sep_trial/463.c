#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_463(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsTagSignature tagSig;
    const void *tagData;
    cmsUInt32Number tagSize;

    // Initialize variables
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Ensure size is sufficient for tag signature and data
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract tag signature and data from input
    tagSig = *(cmsTagSignature *)data;
    tagData = (const void *)(data + sizeof(cmsTagSignature));
    tagSize = (cmsUInt32Number)(size - sizeof(cmsTagSignature));

    // Call the function-under-test
    cmsWriteRawTag(hProfile, tagSig, tagData, tagSize);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}