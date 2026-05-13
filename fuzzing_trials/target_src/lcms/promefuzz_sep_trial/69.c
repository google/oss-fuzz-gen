// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsDictAddEntry at cmsnamed.c:1137:19 in lcms2.h
// cmsDictAlloc at cmsnamed.c:1090:21 in lcms2.h
// cmsDictDup at cmsnamed.c:1161:21 in lcms2.h
// cmsDictGetEntryList at cmsnamed.c:1189:31 in lcms2.h
// cmsDictNextEntry at cmsnamed.c:1198:31 in lcms2.h
// cmsDictFree at cmsnamed.c:1101:16 in lcms2.h
// cmsDictFree at cmsnamed.c:1101:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "lcms2.h"

static void fuzz_cmsDictAddEntry(cmsHANDLE hDict, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(wchar_t) * 2) return;

    size_t nameLen = (Size / sizeof(wchar_t)) / 2;
    size_t valueLen = nameLen;

    wchar_t* Name = (wchar_t*)malloc((nameLen + 1) * sizeof(wchar_t));
    wchar_t* Value = (wchar_t*)malloc((valueLen + 1) * sizeof(wchar_t));

    if (!Name || !Value) {
        free(Name);
        free(Value);
        return;
    }

    memcpy(Name, Data, nameLen * sizeof(wchar_t));
    Name[nameLen] = L'\0';

    memcpy(Value, Data + nameLen * sizeof(wchar_t), valueLen * sizeof(wchar_t));
    Value[valueLen] = L'\0';

    cmsMLU* DisplayName = NULL;
    cmsMLU* DisplayValue = NULL;

    cmsDictAddEntry(hDict, Name, Value, DisplayName, DisplayValue);

    free(Name);
    free(Value);
}

static void fuzz_cmsDictFunctions(const uint8_t *Data, size_t Size) {
    cmsContext context = NULL;  // Assuming context is set up elsewhere
    cmsHANDLE hDict = cmsDictAlloc(context);
    if (!hDict) return;

    fuzz_cmsDictAddEntry(hDict, Data, Size);

    cmsHANDLE hDictDup = cmsDictDup(hDict);
    if (hDictDup) {
        const cmsDICTentry* entryList = cmsDictGetEntryList(hDictDup);
        while (entryList != NULL) {
            entryList = cmsDictNextEntry(entryList);
        }
        cmsDictFree(hDictDup);
    }

    cmsDictFree(hDict);
}

int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size) {
    fuzz_cmsDictFunctions(Data, Size);
    return 0;
}