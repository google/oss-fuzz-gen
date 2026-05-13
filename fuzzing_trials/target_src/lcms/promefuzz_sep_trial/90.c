// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8Alloc at cmscgats.c:1454:22 in lcms2.h
// cmsIT8SetSheetType at cmscgats.c:1513:19 in lcms2.h
// cmsIT8Free at cmscgats.c:1170:16 in lcms2.h
// cmsIT8SetTableByLabel at cmscgats.c:2993:15 in lcms2.h
// cmsIT8SetIndexColumn at cmscgats.c:3025:19 in lcms2.h
// cmsIT8SetPropertyMulti at cmscgats.c:1570:19 in lcms2.h
// cmsIT8GetPatchByName at cmscgats.c:2974:15 in lcms2.h
// cmsIT8FindDataFormat at cmscgats.c:2805:15 in lcms2.h
// cmsIT8SetSheetType at cmscgats.c:1513:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

static cmsHANDLE createDummyIT8Handle() {
    // Create a dummy IT8 handle with proper initialization
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (hIT8) {
        cmsIT8SetSheetType(hIT8, "DUMMY_SHEET");
    }
    return hIT8;
}

static void destroyDummyIT8Handle(cmsHANDLE hIT8) {
    cmsIT8Free(hIT8);
}

int LLVMFuzzerTestOneInput_90(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cmsHANDLE hIT8 = createDummyIT8Handle();
    if (hIT8 == NULL) return 0;

    // Use the data to fuzz different functions
    const char *dummyString = "dummy";

    // Ensure null-terminated strings for the functions
    char buffer[256];
    size_t copySize = (Size < sizeof(buffer)) ? Size : sizeof(buffer) - 1;
    memcpy(buffer, Data, copySize);
    buffer[copySize] = '\0';

    // Fuzz cmsIT8SetTableByLabel
    if (Size >= 4) {
        cmsIT8SetTableByLabel(hIT8, buffer, buffer, buffer);
    }

    // Fuzz cmsIT8SetIndexColumn
    if (Size >= 5) {
        cmsIT8SetIndexColumn(hIT8, buffer);
    }

    // Fuzz cmsIT8SetPropertyMulti
    if (Size >= 6) {
        cmsIT8SetPropertyMulti(hIT8, buffer, buffer, dummyString);
    }

    // Fuzz cmsIT8GetPatchByName
    if (Size >= 7) {
        cmsIT8GetPatchByName(hIT8, buffer);
    }

    // Fuzz cmsIT8FindDataFormat
    if (Size >= 8) {
        cmsIT8FindDataFormat(hIT8, buffer);
    }

    // Fuzz cmsIT8SetSheetType
    if (Size >= 9) {
        cmsIT8SetSheetType(hIT8, buffer);
    }

    destroyDummyIT8Handle(hIT8);
    return 0;
}