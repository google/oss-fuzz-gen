#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsHPROFILE) + sizeof(cmsInfoType) + 2) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = *(cmsHPROFILE*)data;
    cmsInfoType infoType = *(cmsInfoType*)(data + sizeof(cmsHPROFILE));
    const char *languageCode = (const char *)(data + sizeof(cmsHPROFILE) + sizeof(cmsInfoType));
    const char *countryCode = (const char *)(data + sizeof(cmsHPROFILE) + sizeof(cmsInfoType) + 1);
    char outputBuffer[256];
    cmsUInt32Number bufferSize = sizeof(outputBuffer);

    // Ensure languageCode and countryCode are null-terminated
    char langCode[3] = {0};
    char country[3] = {0};
    strncpy(langCode, languageCode, 2);
    strncpy(country, countryCode, 2);

    // Call the function-under-test
    cmsUInt32Number result = cmsGetProfileInfoUTF8(hProfile, infoType, langCode, country, outputBuffer, bufferSize);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_17(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
