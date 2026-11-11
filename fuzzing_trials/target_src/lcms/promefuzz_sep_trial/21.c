// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreateLab2ProfileTHR at cmsvirt.c:473:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateLab2Profile at cmsvirt.c:517:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateLab4ProfileTHR at cmsvirt.c:524:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsTempFromWhitePoint at cmswtpnt.c:143:20 in lcms2.h
// cmsCreateLab4Profile at cmsvirt.c:570:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsWhitePointFromTemp at cmswtpnt.c:48:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

static cmsContext create_context() {
    return NULL; // Simplified context creation for fuzzing purposes
}

static void fuzz_cmsCreateLab2ProfileTHR(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    cmsContext ContextID = create_context();
    const cmsCIExyY* WhitePoint = (const cmsCIExyY*) Data;

    cmsHPROFILE profile = cmsCreateLab2ProfileTHR(ContextID, WhitePoint);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
}

static void fuzz_cmsCreateLab2Profile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    const cmsCIExyY* WhitePoint = (const cmsCIExyY*) Data;

    cmsHPROFILE profile = cmsCreateLab2Profile(WhitePoint);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
}

static void fuzz_cmsCreateLab4ProfileTHR(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    cmsContext ContextID = create_context();
    const cmsCIExyY* WhitePoint = (const cmsCIExyY*) Data;

    cmsHPROFILE profile = cmsCreateLab4ProfileTHR(ContextID, WhitePoint);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
}

static void fuzz_cmsTempFromWhitePoint(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    cmsFloat64Number TempK;
    const cmsCIExyY* WhitePoint = (const cmsCIExyY*) Data;

    cmsTempFromWhitePoint(&TempK, WhitePoint);
}

static void fuzz_cmsCreateLab4Profile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIExyY)) return;

    const cmsCIExyY* WhitePoint = (const cmsCIExyY*) Data;

    cmsHPROFILE profile = cmsCreateLab4Profile(WhitePoint);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
}

static void fuzz_cmsWhitePointFromTemp(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsCIExyY WhitePoint;
    cmsFloat64Number TempK = *((cmsFloat64Number*) Data);

    cmsWhitePointFromTemp(&WhitePoint, TempK);
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateLab2ProfileTHR(Data, Size);
    fuzz_cmsCreateLab2Profile(Data, Size);
    fuzz_cmsCreateLab4ProfileTHR(Data, Size);
    fuzz_cmsTempFromWhitePoint(Data, Size);
    fuzz_cmsCreateLab4Profile(Data, Size);
    fuzz_cmsWhitePointFromTemp(Data, Size);

    return 0;
}