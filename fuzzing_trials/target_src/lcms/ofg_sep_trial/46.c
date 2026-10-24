#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile;
    const char *languageCode = "en";
    const char *countryCode = "US";
    wchar_t buffer[256];
    cmsUInt32Number bufferSize = sizeof(buffer) / sizeof(buffer[0]);

    // Ensure the data size is sufficient for creating a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Define an array of possible info types
    cmsInfoType infoTypes[] = { cmsInfoDescription, cmsInfoManufacturer, cmsInfoModel, cmsInfoCopyright };
    int infoTypesCount = sizeof(infoTypes) / sizeof(infoTypes[0]);

    // Iterate over possible info types
    for (int i = 0; i < infoTypesCount; i++) {
        cmsInfoType infoType = infoTypes[i];

        // Call the function-under-test
        cmsGetProfileInfo(hProfile, infoType, languageCode, countryCode, buffer, bufferSize);
    }

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}