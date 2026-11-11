// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsAdaptToIlluminant at cmswtpnt.c:328:19 in lcms2.h
// cmsLab2XYZ at cmspcs.c:161:16 in lcms2.h
// cmsxyY2XYZ at cmspcs.c:102:16 in lcms2.h
// cmsCreateLab4Profile at cmsvirt.c:570:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsD50_xyY at cmswtpnt.c:38:28 in lcms2.h
// cmsD50_XYZ at cmswtpnt.c:31:28 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static void fuzz_cmsAdaptToIlluminant(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIEXYZ) * 3) return;

    cmsCIEXYZ* Result = (cmsCIEXYZ*)malloc(sizeof(cmsCIEXYZ));
    const cmsCIEXYZ* SourceWhitePt = (const cmsCIEXYZ*)Data;
    const cmsCIEXYZ* Illuminant = (const cmsCIEXYZ*)(Data + sizeof(cmsCIEXYZ));
    const cmsCIEXYZ* Value = (const cmsCIEXYZ*)(Data + 2 * sizeof(cmsCIEXYZ));

    cmsBool success = cmsAdaptToIlluminant(Result, SourceWhitePt, Illuminant, Value);
    if (success) {
        // Use Result in some way if needed
    }

    free(Result);
}

static void fuzz_cmsLab2XYZ(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIEXYZ) + sizeof(cmsCIELab)) return;

    const cmsCIEXYZ* WhitePoint = (const cmsCIEXYZ*)Data;
    cmsCIEXYZ* xyz = (cmsCIEXYZ*)malloc(sizeof(cmsCIEXYZ));
    const cmsCIELab* Lab = (const cmsCIELab*)(Data + sizeof(cmsCIEXYZ));

    cmsLab2XYZ(WhitePoint, xyz, Lab);

    free(xyz);
}

static void fuzz_cmsxyY2XYZ(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    cmsCIEXYZ* Dest = (cmsCIEXYZ*)malloc(sizeof(cmsCIEXYZ));
    const cmsCIExyY* Source = (const cmsCIExyY*)Data;

    cmsxyY2XYZ(Dest, Source);

    free(Dest);
}

static void fuzz_cmsCreateLab4Profile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    const cmsCIExyY* WhitePoint = (const cmsCIExyY*)Data;

    cmsHPROFILE profile = cmsCreateLab4Profile(WhitePoint);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
}

int LLVMFuzzerTestOneInput_115(const uint8_t *Data, size_t Size) {
    fuzz_cmsAdaptToIlluminant(Data, Size);
    fuzz_cmsLab2XYZ(Data, Size);
    fuzz_cmsxyY2XYZ(Data, Size);
    fuzz_cmsCreateLab4Profile(Data, Size);

    // Testing cmsD50_xyY and cmsD50_XYZ does not require fuzzing as they return constant pointers
    const cmsCIExyY* d50_xyY = cmsD50_xyY();
    const cmsCIEXYZ* d50_XYZ = cmsD50_XYZ();

    return 0;
}