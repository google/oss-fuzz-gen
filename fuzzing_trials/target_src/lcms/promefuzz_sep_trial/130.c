// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8Alloc at cmscgats.c:1454:22 in lcms2.h
// cmsIT8Free at cmscgats.c:1170:16 in lcms2.h
// cmsIT8DefineDblFormat at cmscgats.c:3041:16 in lcms2.h
// cmsIT8GetProperty at cmscgats.c:1578:23 in lcms2.h
// cmsIT8GetPatchName at cmscgats.c:2955:23 in lcms2.h
// cmsIT8GetPropertyMulti at cmscgats.c:1600:23 in lcms2.h
// cmsIT8GetSheetType at cmscgats.c:1508:23 in lcms2.h
// cmsIT8GetData at cmscgats.c:2862:23 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

static cmsHANDLE initializeIT8Handle() {
    // Simulate a proper initialization of cmsHANDLE
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    return hIT8;
}

static void cleanupIT8Handle(cmsHANDLE hIT8) {
    // Properly free the allocated IT8 handle
    if (hIT8) {
        cmsIT8Free(hIT8);
    }
}

int LLVMFuzzerTestOneInput_130(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Not enough data to process

    cmsHANDLE hIT8 = initializeIT8Handle();
    if (!hIT8) return 0;

    // Ensure the formatter is null-terminated and within a reasonable length
    char formatter[256] = {0};
    if (Size > 1) {
        size_t len = (Size < sizeof(formatter)) ? Size : sizeof(formatter) - 1;
        memcpy(formatter, Data, len);
    }

    cmsIT8DefineDblFormat(hIT8, formatter);

    // Fuzz cmsIT8GetProperty
    const char* prop = (Size > 1) ? (const char*)Data : NULL;
    const char* propValue = cmsIT8GetProperty(hIT8, prop);

    // Fuzz cmsIT8GetPatchName
    char buffer[256];
    int patchIndex = Data[0] % 256; // Simulating a patch index
    const char* patchName = cmsIT8GetPatchName(hIT8, patchIndex, buffer);

    // Fuzz cmsIT8GetPropertyMulti
    const char* subKey = (Size > 2) ? (const char*)(Data + 1) : NULL;
    const char* multiPropValue = cmsIT8GetPropertyMulti(hIT8, prop, subKey);

    // Fuzz cmsIT8GetSheetType
    const char* sheetType = cmsIT8GetSheetType(hIT8);

    // Fuzz cmsIT8GetData
    const char* sample = (Size > 3) ? (const char*)(Data + 2) : NULL;
    const char* dataValue = cmsIT8GetData(hIT8, prop, sample);

    // Cleanup
    cleanupIT8Handle(hIT8);

    return 0;
}