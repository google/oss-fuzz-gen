#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }
    
    cmsInfoType infoType = cmsInfoDescription;
    const char *languageCode = "en";
    const char *countryCode = "US";
    char buffer[256];
    cmsUInt32Number bufferSize = sizeof(buffer);

    // Call the function-under-test
    cmsGetProfileInfoUTF8(hProfile, infoType, languageCode, countryCode, buffer, bufferSize);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}