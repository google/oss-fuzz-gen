// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsMLUalloc at cmsnamed.c:33:19 in lcms2.h
// cmsMLUsetWide at cmsnamed.c:413:20 in lcms2.h
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsMLUfree at cmsnamed.c:476:16 in lcms2.h
// cmsMLUgetWide at cmsnamed.c:629:27 in lcms2.h
// cmsMLUgetUTF8 at cmsnamed.c:590:27 in lcms2.h
// cmsMLUgetASCII at cmsnamed.c:542:27 in lcms2.h
// cmsGetProfileInfo at cmsio1.c:1016:27 in lcms2.h
// cmsGetProfileInfoASCII at cmsio1.c:1027:28 in lcms2.h
// cmsGetProfileInfoUTF8 at cmsio1.c:1037:28 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsMLUfree at cmsnamed.c:476:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include "lcms2.h"

static cmsMLU* createDummyMLU() {
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (mlu) {
        cmsMLUsetWide(mlu, "en", "US", L"Sample Text");
    }
    return mlu;
}

static cmsHPROFILE createDummyProfile() {
    return cmsOpenProfileFromFile("./dummy_file", "r");
}

int LLVMFuzzerTestOneInput_86(const uint8_t *Data, size_t Size) {
    if (Size < 6) return 0;

    cmsMLU* mlu = createDummyMLU();
    if (!mlu) return 0;

    cmsHPROFILE hProfile = createDummyProfile();
    if (!hProfile) {
        cmsMLUfree(mlu);
        return 0;
    }

    char LanguageCode[3] = {Data[0], Data[1], '\0'};
    char CountryCode[3] = {Data[2], Data[3], '\0'};
    cmsInfoType Info = (cmsInfoType)(Data[4] % 5);
    cmsUInt32Number BufferSize = Data[5] + 1; // Ensure non-zero buffer size

    wchar_t WideBuffer[256];
    char ASCIIBuffer[256];
    char UTF8Buffer[256];

    cmsMLUgetWide(mlu, LanguageCode, CountryCode, WideBuffer, BufferSize);
    cmsMLUgetUTF8(mlu, LanguageCode, CountryCode, UTF8Buffer, BufferSize);
    cmsMLUgetASCII(mlu, LanguageCode, CountryCode, ASCIIBuffer, BufferSize);

    cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, WideBuffer, BufferSize);
    cmsGetProfileInfoASCII(hProfile, Info, LanguageCode, CountryCode, ASCIIBuffer, BufferSize);
    cmsGetProfileInfoUTF8(hProfile, Info, LanguageCode, CountryCode, UTF8Buffer, BufferSize);

    cmsCloseProfile(hProfile);
    cmsMLUfree(mlu);

    return 0;
}