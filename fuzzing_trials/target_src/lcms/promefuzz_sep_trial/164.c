// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsMLUalloc at cmsnamed.c:33:19 in lcms2.h
// cmsMLUgetUTF8 at cmsnamed.c:590:27 in lcms2.h
// cmsMLUgetASCII at cmsnamed.c:542:27 in lcms2.h
// cmsMLUtranslationsCount at cmsnamed.c:689:27 in lcms2.h
// cmsMLUdup at cmsnamed.c:430:19 in lcms2.h
// cmsMLUfree at cmsnamed.c:476:16 in lcms2.h
// cmsMLUfree at cmsnamed.c:476:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static void FuzzMLUFunctions(const uint8_t *Data, size_t Size) {
    cmsContext context = NULL;
    cmsUInt32Number nItems = (Size > 0) ? Data[0] : 2;
    
    cmsMLU* mlu = cmsMLUalloc(context, nItems);
    if (!mlu) return;

    // Fuzz cmsMLUgetUTF8 and cmsMLUgetASCII
    char langCode[3] = "en";
    char countryCode[3] = "US";
    char buffer[256];
    cmsUInt32Number bufferSize = sizeof(buffer);

    cmsMLUgetUTF8(mlu, langCode, countryCode, buffer, bufferSize);
    cmsMLUgetASCII(mlu, langCode, countryCode, buffer, bufferSize);

    // Fuzz cmsMLUtranslationsCount
    cmsUInt32Number count = cmsMLUtranslationsCount(mlu);

    // Fuzz cmsMLUdup
    cmsMLU* mluDup = cmsMLUdup(mlu);
    if (mluDup) {
        cmsMLUfree(mluDup);
    }

    // Cleanup
    cmsMLUfree(mlu);
}

int LLVMFuzzerTestOneInput_164(const uint8_t *Data, size_t Size) {
    FuzzMLUFunctions(Data, Size);
    return 0;
}