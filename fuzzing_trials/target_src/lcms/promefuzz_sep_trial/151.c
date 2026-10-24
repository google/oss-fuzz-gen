// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsAppendNamedColor at cmsnamed.c:815:20 in lcms2.h
// cmsNamedColorInfo at cmsnamed.c:855:20 in lcms2.h
// cmsAppendNamedColor at cmsnamed.c:815:20 in lcms2.h
// cmsDupNamedColorList at cmsnamed.c:787:30 in lcms2.h
// cmsNamedColorIndex at cmsnamed.c:882:26 in lcms2.h
// cmsFreeNamedColorList at cmsnamed.c:780:16 in lcms2.h
// cmsFreeNamedColorList at cmsnamed.c:780:16 in lcms2.h
// cmsAllocNamedColorList at cmsnamed.c:749:30 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsNAMEDCOLORLIST* create_dummy_named_color_list() {
    cmsNAMEDCOLORLIST* list = cmsAllocNamedColorList(NULL, 10, 3, "prefix", "suffix");
    if (list != NULL) {
        cmsUInt16Number pcs[3] = {0, 0, 0};
        cmsUInt16Number colorant[cmsMAXCHANNELS] = {0};
        cmsAppendNamedColor(list, "DummyColor", pcs, colorant);
    }
    return list;
}

int LLVMFuzzerTestOneInput_151(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy named color list
    cmsNAMEDCOLORLIST* namedColorList = create_dummy_named_color_list();
    if (!namedColorList) return 0;

    // Buffers for cmsNamedColorInfo
    char Name[255];
    char Prefix[33];
    char Suffix[33];
    cmsUInt16Number PCS[3];
    cmsUInt16Number Colorant[cmsMAXCHANNELS];

    // Fuzz cmsNamedColorInfo
    cmsNamedColorInfo(namedColorList, Data[0] % 10, Name, Prefix, Suffix, PCS, Colorant);

    // Fuzz cmsAppendNamedColor
    if (Size >= 5) { // Ensure there is enough data
        cmsUInt16Number pcs[3] = {Data[1], Data[2], Data[3]};
        cmsUInt16Number colorant[cmsMAXCHANNELS] = {0}; // Initialize the array
        colorant[0] = Data[4]; // Assign only if Size allows

        // Ensure the name is not longer than the maximum allowed by lcms
        size_t maxNameLength = cmsMAX_PATH - 1;
        size_t nameLength = Size < maxNameLength ? Size : maxNameLength;
        char safeName[cmsMAX_PATH];
        memcpy(safeName, Data, nameLength);
        safeName[nameLength] = '\0';

        cmsAppendNamedColor(namedColorList, safeName, pcs, colorant);
    }

    // Fuzz cmsDupNamedColorList
    cmsNAMEDCOLORLIST* duplicatedList = cmsDupNamedColorList(namedColorList);

    // Fuzz cmsNamedColorIndex with a null-terminated string
    char* safeName = (char*)malloc(Size + 1);
    if (safeName) {
        memcpy(safeName, Data, Size);
        safeName[Size] = '\0'; // Ensure null-termination
        cmsNamedColorIndex(namedColorList, safeName);
        free(safeName);
    }

    // Clean up
    cmsFreeNamedColorList(namedColorList);
    if (duplicatedList) {
        cmsFreeNamedColorList(duplicatedList);
    }

    return 0;
}