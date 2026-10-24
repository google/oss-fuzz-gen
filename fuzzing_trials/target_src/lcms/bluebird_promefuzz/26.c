#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "lcms2.h"
#include "/src/lcms/include/lcms2_plugin.h"

static cmsHPROFILE openDummyProfile() {
    // Properly simulate a profile handle. Normally, you would load a real profile.
    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        // Create a dummy profile if opening fails
        hProfile = cmsCreate_sRGBProfile();
    }
    return hProfile;
}

static void closeDummyProfile(cmsHPROFILE hProfile) {
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 7) return 0; // Ensure there's enough data for the minimum required input

    cmsHPROFILE hProfile = openDummyProfile();
    if (!hProfile) return 0;

    cmsContext ContextID = NULL; // For simplicity, using NULL context
    cmsInfoType Info = (cmsInfoType)Data[0];
    char LanguageCode[3] = { (char)Data[1], (char)Data[2], '\0' };
    char CountryCode[3] = { (char)Data[3], (char)Data[4], '\0' };
    cmsUInt32Number BufferSize = (cmsUInt32Number)Data[5] % 256 + 1; // Ensure non-zero buffer size

    wchar_t* Buffer = (wchar_t*)_cmsMalloc(ContextID, BufferSize * sizeof(wchar_t));
    if (!Buffer) {
        closeDummyProfile(hProfile);
        return 0;
    }

    cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, Buffer, BufferSize);

    // Reallocate buffer to test _cmsMalloc again
    _cmsFree(ContextID, Buffer);
    Buffer = (wchar_t*)_cmsMalloc(ContextID, BufferSize * sizeof(wchar_t));
    if (!Buffer) {
        closeDummyProfile(hProfile);
        return 0;
    }

    cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, Buffer, BufferSize);

    _cmsFree(ContextID, Buffer);
    closeDummyProfile(hProfile);

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
