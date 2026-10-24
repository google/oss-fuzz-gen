// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsIsTag at cmsio0.c:709:19 in lcms2.h
// cmsSaveProfileToMem at cmsio0.c:1537:19 in lcms2.h
// cmsSaveProfileToMem at cmsio0.c:1537:19 in lcms2.h
// cmsGetHeaderCreationDateTime at cmsio0.c:1063:20 in lcms2.h
// cmsSaveProfileToFile at cmsio0.c:1503:20 in lcms2.h
// cmsMD5computeID at cmsmd5.c:257:19 in lcms2.h
// cmsGetTagCount at cmsio0.c:581:26 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "lcms2.h"

static cmsHPROFILE createDummyProfile() {
    // For simplicity, create a profile using a built-in profile (e.g., sRGB)
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    return hProfile;
}

static void fuzzCmsIsTag(cmsHPROFILE hProfile, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsTagSignature)) return;
    cmsTagSignature sig = *(cmsTagSignature*)Data;
    cmsIsTag(hProfile, sig);
}

static void fuzzCmsSaveProfileToMem(cmsHPROFILE hProfile) {
    cmsUInt32Number BytesNeeded = 0;
    cmsSaveProfileToMem(hProfile, NULL, &BytesNeeded);
    if (BytesNeeded > 0) {
        void *MemPtr = malloc(BytesNeeded);
        if (MemPtr) {
            cmsSaveProfileToMem(hProfile, MemPtr, &BytesNeeded);
            free(MemPtr);
        }
    }
}

static void fuzzCmsGetHeaderCreationDateTime(cmsHPROFILE hProfile) {
    struct tm Dest;
    cmsGetHeaderCreationDateTime(hProfile, &Dest);
}

static void fuzzCmsSaveProfileToFile(cmsHPROFILE hProfile) {
    cmsSaveProfileToFile(hProfile, "./dummy_file");
}

static void fuzzCmsMD5computeID(cmsHPROFILE hProfile) {
    cmsMD5computeID(hProfile);
}

static void fuzzCmsGetTagCount(cmsHPROFILE hProfile) {
    cmsGetTagCount(hProfile);
}

int LLVMFuzzerTestOneInput_134(const uint8_t *Data, size_t Size) {
    cmsHPROFILE hProfile = createDummyProfile();
    if (!hProfile) return 0;

    fuzzCmsIsTag(hProfile, Data, Size);
    fuzzCmsSaveProfileToMem(hProfile);
    fuzzCmsGetHeaderCreationDateTime(hProfile);
    fuzzCmsSaveProfileToFile(hProfile);
    fuzzCmsMD5computeID(hProfile);
    fuzzCmsGetTagCount(hProfile);

    cmsCloseProfile(hProfile);
    return 0;
}