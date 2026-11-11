#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsInfoType infoType;
    char languageCode[3] = "en";
    char countryCode[3] = "US";
    char buffer[256];
    cmsUInt32Number bufferSize = sizeof(buffer);

    // Ensure the data is large enough to contain necessary information
    if (size < sizeof(cmsInfoType)) {
        return 0;
    }

    // Initialize the profile using the data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract the infoType from the data
    memcpy(&infoType, data, sizeof(cmsInfoType));

    // Call the function-under-test
    cmsGetProfileInfoASCII(hProfile, infoType, languageCode, countryCode, buffer, bufferSize);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
