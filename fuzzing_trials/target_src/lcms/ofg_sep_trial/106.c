#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Ensure size is large enough to extract necessary data
    if (size < sizeof(cmsUInt32Number) + 2) {
        return 0;
    }

    // Extract a cmsUInt32Number from the data
    cmsUInt32Number profileData = *(cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Extract cmsInfoType from the data
    cmsInfoType infoType = (cmsInfoType)(*data);
    data++;
    size--;

    // Create a dummy cmsHPROFILE
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(&profileData, sizeof(cmsUInt32Number));
    if (hProfile == NULL) {
        return 0;
    }

    // Prepare buffers for language, country, and info
    const char *languageCode = "en";
    const char *countryCode = "US";
    char infoBuffer[256];

    // Call the function-under-test
    cmsUInt32Number result = cmsGetProfileInfoASCII(hProfile, infoType, languageCode, countryCode, infoBuffer, sizeof(infoBuffer));

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}