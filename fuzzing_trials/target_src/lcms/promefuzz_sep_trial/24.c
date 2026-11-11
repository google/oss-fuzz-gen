// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsFloat2LabEncodedV2 at cmspcs.c:254:16 in lcms2.h
// cmsLabEncoded2FloatV2 at cmspcs.c:218:16 in lcms2.h
// cmsDeltaE at cmspcs.c:438:28 in lcms2.h
// cmsFloat2LabEncoded at cmspcs.c:298:16 in lcms2.h
// cmsBFDdeltaE at cmspcs.c:497:28 in lcms2.h
// cmsLabEncoded2Float at cmspcs.c:226:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "lcms2.h"

static void fuzz_cmsFloat2LabEncodedV2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab)) return;

    cmsCIELab Lab;
    cmsUInt16Number wLab[3];

    memcpy(&Lab, Data, sizeof(cmsCIELab));
    cmsFloat2LabEncodedV2(wLab, &Lab);
}

static void fuzz_cmsLabEncoded2FloatV2(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(cmsUInt16Number)) return;

    cmsCIELab Lab;
    cmsUInt16Number wLab[3];

    memcpy(wLab, Data, 3 * sizeof(cmsUInt16Number));
    cmsLabEncoded2FloatV2(&Lab, wLab);
}

static void fuzz_cmsDeltaE(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(cmsCIELab)) return;

    cmsCIELab Lab1, Lab2;

    memcpy(&Lab1, Data, sizeof(cmsCIELab));
    memcpy(&Lab2, Data + sizeof(cmsCIELab), sizeof(cmsCIELab));
    cmsDeltaE(&Lab1, &Lab2);
}

static void fuzz_cmsFloat2LabEncoded(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab)) return;

    cmsCIELab Lab;
    cmsUInt16Number wLab[3];

    memcpy(&Lab, Data, sizeof(cmsCIELab));
    cmsFloat2LabEncoded(wLab, &Lab);
}

static void fuzz_cmsBFDdeltaE(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(cmsCIELab)) return;

    cmsCIELab Lab1, Lab2;

    memcpy(&Lab1, Data, sizeof(cmsCIELab));
    memcpy(&Lab2, Data + sizeof(cmsCIELab), sizeof(cmsCIELab));
    cmsBFDdeltaE(&Lab1, &Lab2);
}

static void fuzz_cmsLabEncoded2Float(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(cmsUInt16Number)) return;

    cmsCIELab Lab;
    cmsUInt16Number wLab[3];

    memcpy(wLab, Data, 3 * sizeof(cmsUInt16Number));
    cmsLabEncoded2Float(&Lab, wLab);
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    fuzz_cmsFloat2LabEncodedV2(Data, Size);
    fuzz_cmsLabEncoded2FloatV2(Data, Size);
    fuzz_cmsDeltaE(Data, Size);
    fuzz_cmsFloat2LabEncoded(Data, Size);
    fuzz_cmsBFDdeltaE(Data, Size);
    fuzz_cmsLabEncoded2Float(Data, Size);
    return 0;
}