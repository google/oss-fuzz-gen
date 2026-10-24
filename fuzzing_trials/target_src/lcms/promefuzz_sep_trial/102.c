// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8SetIndexColumn at cmscgats.c:3025:19 in lcms2.h
// cmsIT8GetPatchName at cmscgats.c:2955:23 in lcms2.h
// cmsIT8GetPatchByName at cmscgats.c:2974:15 in lcms2.h
// cmsIT8FindDataFormat at cmscgats.c:2805:15 in lcms2.h
// cmsIT8EnumDataFormat at cmscgats.c:2650:15 in lcms2.h
// cmsNamedColorIndex at cmsnamed.c:882:26 in lcms2.h
// cmsIT8Alloc at cmscgats.c:1454:22 in lcms2.h
// cmsAllocNamedColorList at cmsnamed.c:749:30 in lcms2.h
// cmsIT8Free at cmscgats.c:1170:16 in lcms2.h
// cmsFreeNamedColorList at cmsnamed.c:780:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

static void fuzz_cmsIT8SetIndexColumn(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size > 0 && hIT8 != NULL) {
        char sampleName[256];
        size_t len = Size < 255 ? Size : 255;
        memcpy(sampleName, Data, len);
        sampleName[len] = '\0';
        cmsIT8SetIndexColumn(hIT8, sampleName);
    }
}

static void fuzz_cmsIT8GetPatchName(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(int) && hIT8 != NULL) {
        int patchIndex;
        memcpy(&patchIndex, Data, sizeof(int));
        char buffer[256];
        cmsIT8GetPatchName(hIT8, patchIndex, buffer);
    }
}

static void fuzz_cmsIT8GetPatchByName(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size > 0 && hIT8 != NULL) {
        char patchName[256];
        size_t len = Size < 255 ? Size : 255;
        memcpy(patchName, Data, len);
        patchName[len] = '\0';
        cmsIT8GetPatchByName(hIT8, patchName);
    }
}

static void fuzz_cmsIT8FindDataFormat(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size > 0 && hIT8 != NULL) {
        char sampleName[256];
        size_t len = Size < 255 ? Size : 255;
        memcpy(sampleName, Data, len);
        sampleName[len] = '\0';
        cmsIT8FindDataFormat(hIT8, sampleName);
    }
}

static void fuzz_cmsIT8EnumDataFormat(cmsHANDLE hIT8) {
    if (hIT8 != NULL) {
        char **sampleNames = NULL;
        cmsIT8EnumDataFormat(hIT8, &sampleNames);
        // Normally, you would free sampleNames here if it was allocated
    }
}

static void fuzz_cmsNamedColorIndex(const cmsNAMEDCOLORLIST *v, const uint8_t *Data, size_t Size) {
    if (Size > 0 && v != NULL) {
        char colorName[256];
        size_t len = Size < 255 ? Size : 255;
        memcpy(colorName, Data, len);
        colorName[len] = '\0';
        cmsNamedColorIndex(v, colorName);
    }
}

int LLVMFuzzerTestOneInput_102(const uint8_t *Data, size_t Size) {
    cmsHANDLE hIT8 = cmsIT8Alloc(0); // Allocate a valid IT8 handle
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 0, 0, "", ""); // Allocate a valid named color list

    fuzz_cmsIT8SetIndexColumn(hIT8, Data, Size);
    fuzz_cmsIT8GetPatchName(hIT8, Data, Size);
    fuzz_cmsIT8GetPatchByName(hIT8, Data, Size);
    fuzz_cmsIT8FindDataFormat(hIT8, Data, Size);
    fuzz_cmsIT8EnumDataFormat(hIT8);
    fuzz_cmsNamedColorIndex(namedColorList, Data, Size);

    cmsIT8Free(hIT8); // Clean up IT8 handle
    cmsFreeNamedColorList(namedColorList); // Clean up named color list

    return 0;
}