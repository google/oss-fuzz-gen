// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsLab2LCh at cmspcs.c:349:16 in lcms2.h
// cmsCIECAM02Init at cmscam02.c:363:22 in lcms2.h
// cmsCIECAM02Forward at cmscam02.c:440:16 in lcms2.h
// cmsCIECAM02Done at cmscam02.c:432:16 in lcms2.h
// cmsCIECAM02Init at cmscam02.c:363:22 in lcms2.h
// cmsCIECAM02Done at cmscam02.c:432:16 in lcms2.h
// cmsCIECAM02Init at cmscam02.c:363:22 in lcms2.h
// cmsCIECAM02Reverse at cmscam02.c:466:16 in lcms2.h
// cmsCIECAM02Done at cmscam02.c:432:16 in lcms2.h
// cmsCIE2000DeltaE at cmspcs.c:589:28 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static void fuzz_cmsLab2LCh(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab)) return;

    cmsCIELab Lab;
    cmsCIELCh LCh;
    memcpy(&Lab, Data, sizeof(cmsCIELab));

    cmsLab2LCh(&LCh, &Lab);
}

static void fuzz_cmsCIECAM02Forward(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIEXYZ)) return;

    // Initialize a dummy viewing condition for model creation
    cmsViewingConditions VC;
    cmsContext ContextID = NULL;
    cmsHANDLE hModel = cmsCIECAM02Init(ContextID, &VC);
    if (hModel == NULL) return;

    cmsCIEXYZ XYZ;
    cmsJCh JCh;
    memcpy(&XYZ, Data, sizeof(cmsCIEXYZ));

    cmsCIECAM02Forward(hModel, &XYZ, &JCh);

    cmsCIECAM02Done(hModel);
}

static void fuzz_cmsCIECAM02Init(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsViewingConditions)) return;

    cmsContext ContextID = NULL;
    cmsViewingConditions VC;
    memcpy(&VC, Data, sizeof(cmsViewingConditions));

    cmsHANDLE hModel = cmsCIECAM02Init(ContextID, &VC);
    if (hModel) {
        cmsCIECAM02Done(hModel);
    }
}

static void fuzz_cmsCIECAM02Reverse(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsJCh)) return;

    // Initialize a dummy viewing condition for model creation
    cmsViewingConditions VC;
    cmsContext ContextID = NULL;
    cmsHANDLE hModel = cmsCIECAM02Init(ContextID, &VC);
    if (hModel == NULL) return;

    cmsJCh JCh;
    cmsCIEXYZ XYZ;
    memcpy(&JCh, Data, sizeof(cmsJCh));

    cmsCIECAM02Reverse(hModel, &JCh, &XYZ);

    cmsCIECAM02Done(hModel);
}

static void fuzz_cmsCIE2000DeltaE(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(cmsCIELab) + 3 * sizeof(cmsFloat64Number)) return;

    cmsCIELab Lab1, Lab2;
    cmsFloat64Number Kl, Kc, Kh;
    memcpy(&Lab1, Data, sizeof(cmsCIELab));
    memcpy(&Lab2, Data + sizeof(cmsCIELab), sizeof(cmsCIELab));
    memcpy(&Kl, Data + 2 * sizeof(cmsCIELab), sizeof(cmsFloat64Number));
    memcpy(&Kc, Data + 2 * sizeof(cmsCIELab) + sizeof(cmsFloat64Number), sizeof(cmsFloat64Number));
    memcpy(&Kh, Data + 2 * sizeof(cmsCIELab) + 2 * sizeof(cmsFloat64Number), sizeof(cmsFloat64Number));

    cmsFloat64Number deltaE = cmsCIE2000DeltaE(&Lab1, &Lab2, Kl, Kc, Kh);
}

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    fuzz_cmsLab2LCh(Data, Size);
    fuzz_cmsCIECAM02Forward(Data, Size);
    fuzz_cmsCIECAM02Init(Data, Size);
    fuzz_cmsCIECAM02Reverse(Data, Size);
    fuzz_cmsCIE2000DeltaE(Data, Size);

    return 0;
}