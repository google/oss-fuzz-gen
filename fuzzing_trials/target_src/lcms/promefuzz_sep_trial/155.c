// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsFloat2LabEncodedV2 at cmspcs.c:254:16 in lcms2.h
// cmsLabEncoded2FloatV2 at cmspcs.c:218:16 in lcms2.h
// cmsLab2LCh at cmspcs.c:349:16 in lcms2.h
// cmsLCh2Lab at cmspcs.c:358:16 in lcms2.h
// cmsFloat2LabEncoded at cmspcs.c:298:16 in lcms2.h
// cmsLabEncoded2Float at cmspcs.c:226:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lcms2.h"

static void fuzz_cmsFloat2LabEncodedV2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab)) return;

    cmsUInt16Number wLab[3];
    cmsCIELab Lab;

    memcpy(&Lab, Data, sizeof(cmsCIELab));
    cmsFloat2LabEncodedV2(wLab, &Lab);
}

static void fuzz_cmsLabEncoded2FloatV2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number) * 3) return;

    cmsCIELab Lab;
    cmsUInt16Number wLab[3];

    memcpy(wLab, Data, sizeof(cmsUInt16Number) * 3);
    cmsLabEncoded2FloatV2(&Lab, wLab);
}

static void fuzz_cmsLab2LCh(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab)) return;

    cmsCIELCh LCh;
    cmsCIELab Lab;

    memcpy(&Lab, Data, sizeof(cmsCIELab));
    cmsLab2LCh(&LCh, &Lab);
}

static void fuzz_cmsLCh2Lab(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELCh)) return;

    cmsCIELab Lab;
    cmsCIELCh LCh;

    memcpy(&LCh, Data, sizeof(cmsCIELCh));
    cmsLCh2Lab(&Lab, &LCh);
}

static void fuzz_cmsFloat2LabEncoded(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab)) return;

    cmsUInt16Number wLab[3];
    cmsCIELab Lab;

    memcpy(&Lab, Data, sizeof(cmsCIELab));
    cmsFloat2LabEncoded(wLab, &Lab);
}

static void fuzz_cmsLabEncoded2Float(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number) * 3) return;

    cmsCIELab Lab;
    cmsUInt16Number wLab[3];

    memcpy(wLab, Data, sizeof(cmsUInt16Number) * 3);
    cmsLabEncoded2Float(&Lab, wLab);
}

int LLVMFuzzerTestOneInput_155(const uint8_t *Data, size_t Size) {
    fuzz_cmsFloat2LabEncodedV2(Data, Size);
    fuzz_cmsLabEncoded2FloatV2(Data, Size);
    fuzz_cmsLab2LCh(Data, Size);
    fuzz_cmsLCh2Lab(Data, Size);
    fuzz_cmsFloat2LabEncoded(Data, Size);
    fuzz_cmsLabEncoded2Float(Data, Size);
    return 0;
}