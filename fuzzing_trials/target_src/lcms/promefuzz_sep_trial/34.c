// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetContextUserData at cmsplugin.c:1021:17 in lcms2.h
// cmsGetProfileContextID at cmsio0.c:571:22 in lcms2.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
// cmsCreate_OkLabProfile at cmsvirt.c:690:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsDupContext at cmsplugin.c:893:22 in lcms2.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
// cmsCreateContext at cmsplugin.c:824:22 in lcms2.h
// cmsCreate_sRGBProfileTHR at cmsvirt.c:653:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreate_sRGBProfileTHR at cmsvirt.c:653:23 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static void fuzz_cmsCreate_sRGBProfileTHR(cmsContext ContextID) {
    cmsHPROFILE hProfile = cmsCreate_sRGBProfileTHR(ContextID);
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }
}

static void fuzz_cmsGetContextUserData(cmsContext ContextID) {
    void* userData = cmsGetContextUserData(ContextID);
    (void)userData; // Suppress unused variable warning
}

static void fuzz_cmsGetProfileContextID(cmsHPROFILE hProfile) {
    cmsContext contextID = cmsGetProfileContextID(hProfile);
    (void)contextID; // Suppress unused variable warning
}

static void fuzz_cmsDeleteContext(cmsContext ContextID) {
    if (ContextID != NULL) {
        cmsDeleteContext(ContextID);
    }
}

static void fuzz_cmsCreate_OkLabProfile(cmsContext ContextID) {
    cmsHPROFILE hProfile = cmsCreate_OkLabProfile(ContextID);
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }
}

static void fuzz_cmsDupContext(cmsContext ContextID) {
    if (ContextID != NULL) {
        cmsContext newContext = cmsDupContext(ContextID, NULL);
        if (newContext != NULL) {
            cmsDeleteContext(newContext);
        }
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsContext)) {
        return 0;
    }

    cmsContext ContextID = cmsCreateContext(NULL, NULL);
    if (ContextID == NULL) {
        return 0;
    }

    fuzz_cmsCreate_sRGBProfileTHR(ContextID);
    fuzz_cmsGetContextUserData(ContextID);
    fuzz_cmsCreate_OkLabProfile(ContextID);
    fuzz_cmsDupContext(ContextID);

    cmsHPROFILE dummyProfile = cmsCreate_sRGBProfileTHR(ContextID);
    if (dummyProfile != NULL) {
        fuzz_cmsGetProfileContextID(dummyProfile);
        cmsCloseProfile(dummyProfile);
    }

    fuzz_cmsDeleteContext(ContextID);

    return 0;
}