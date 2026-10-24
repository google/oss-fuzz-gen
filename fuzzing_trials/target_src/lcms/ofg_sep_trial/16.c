#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function-under-test
    cmsHPROFILE hProfile;
    cmsInfoType infoType;
    const char *languageCode = "en";
    const char *countryCode = "US";
    char buffer[256];
    cmsUInt32Number bufferSize = sizeof(buffer);

    // Ensure the data size is sufficient to extract necessary information
    if (size < sizeof(cmsInfoType)) {
        return 0;
    }

    // Use the first few bytes of data to set infoType
    memcpy(&infoType, data, sizeof(cmsInfoType));

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsGetProfileInfoUTF8(hProfile, infoType, languageCode, countryCode, buffer, bufferSize);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}