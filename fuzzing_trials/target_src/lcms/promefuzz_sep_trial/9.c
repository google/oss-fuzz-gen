// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsMLUfree at cmsnamed.c:476:16 in lcms2.h
// cmsMLUgetWide at cmsnamed.c:629:27 in lcms2.h
// cmsMLUgetTranslation at cmsnamed.c:663:26 in lcms2.h
// cmsMLUsetUTF8 at cmsnamed.c:368:19 in lcms2.h
// cmsMLUsetWide at cmsnamed.c:413:20 in lcms2.h
// cmsMLUtranslationsCodes at cmsnamed.c:696:19 in lcms2.h
// cmsMLUsetASCII at cmsnamed.c:336:19 in lcms2.h
// cmsMLUalloc at cmsnamed.c:33:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include "lcms2.h"

static cmsMLU* createDummyMLU() {
    return cmsMLUalloc(NULL, 0);
}

static void freeDummyMLU(cmsMLU* mlu) {
    if (mlu) {
        cmsMLUfree(mlu);
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 6) return 0; // Ensure enough data for language and country codes

    cmsMLU* mlu = createDummyMLU();
    if (!mlu) return 0;

    char LanguageCode[3] = { Data[0], Data[1], '\0' };
    char CountryCode[3] = { Data[2], Data[3], '\0' };

    wchar_t WideBuffer[256];
    cmsUInt32Number BufferSize = sizeof(WideBuffer) / sizeof(WideBuffer[0]);

    // Ensure UTF8String is null-terminated
    size_t UTF8StringLength = Size - 4;
    char* UTF8String = (char*)malloc(UTF8StringLength + 1);
    if (!UTF8String) {
        freeDummyMLU(mlu);
        return 0;
    }
    memcpy(UTF8String, &Data[4], UTF8StringLength);
    UTF8String[UTF8StringLength] = '\0';

    // Fuzz cmsMLUgetWide
    cmsMLUgetWide(mlu, LanguageCode, CountryCode, WideBuffer, BufferSize);

    // Fuzz cmsMLUgetTranslation
    char ObtainedLanguage[3];
    char ObtainedCountry[3];
    cmsMLUgetTranslation(mlu, LanguageCode, CountryCode, ObtainedLanguage, ObtainedCountry);

    // Fuzz cmsMLUsetUTF8
    cmsMLUsetUTF8(mlu, LanguageCode, CountryCode, UTF8String);

    // Fuzz cmsMLUsetWide
    cmsMLUsetWide(mlu, LanguageCode, CountryCode, WideBuffer);

    // Fuzz cmsMLUtranslationsCodes
    cmsMLUtranslationsCodes(mlu, 0, LanguageCode, CountryCode);

    // Fuzz cmsMLUsetASCII
    cmsMLUsetASCII(mlu, LanguageCode, CountryCode, UTF8String);

    free(UTF8String);
    freeDummyMLU(mlu);
    return 0;
}