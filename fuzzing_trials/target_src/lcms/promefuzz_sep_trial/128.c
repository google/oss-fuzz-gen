// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8Alloc at cmscgats.c:1454:22 in lcms2.h
// cmsIT8SetSheetType at cmscgats.c:1513:19 in lcms2.h
// cmsIT8Free at cmscgats.c:1170:16 in lcms2.h
// cmsIT8SetIndexColumn at cmscgats.c:3025:19 in lcms2.h
// cmsstrcasecmp at cmserr.c:39:15 in lcms2.h
// cmsIT8GetPatchByName at cmscgats.c:2974:15 in lcms2.h
// cmsIT8FindDataFormat at cmscgats.c:2805:15 in lcms2.h
// cmsIT8SetSheetType at cmscgats.c:1513:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsHANDLE create_dummy_it8_handle() {
    // Properly simulate an IT8 handle structure
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (hIT8) {
        cmsIT8SetSheetType(hIT8, "DUMMY");
    }
    return hIT8;
}

static void free_dummy_it8_handle(cmsHANDLE hIT8) {
    if (hIT8) {
        cmsIT8Free(hIT8);
    }
}

int LLVMFuzzerTestOneInput_128(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there's enough data

    char* sampleName = (char*)malloc(Size + 1);
    if (!sampleName) return 0; // Check allocation success
    memcpy(sampleName, Data, Size);
    sampleName[Size] = '\0';

    cmsHANDLE hIT8 = create_dummy_it8_handle();
    if (!hIT8) {
        free(sampleName);
        return 0;
    }

    // Fuzz cmsIT8SetIndexColumn
    cmsIT8SetIndexColumn(hIT8, sampleName);

    // Fuzz cmsstrcasecmp
    if (Size >= 2) {
        cmsstrcasecmp(sampleName, sampleName + 1);
    }

    // Fuzz cmsIT8GetPatchByName
    cmsIT8GetPatchByName(hIT8, sampleName);

    // Fuzz cmsIT8FindDataFormat
    cmsIT8FindDataFormat(hIT8, sampleName);

    // Fuzz cmsNamedColorIndex
    // Since we cannot directly create a cmsNAMEDCOLORLIST, we will skip fuzzing cmsNamedColorIndex

    // Fuzz cmsIT8SetSheetType
    cmsIT8SetSheetType(hIT8, sampleName);

    free_dummy_it8_handle(hIT8);
    free(sampleName);

    return 0;
}