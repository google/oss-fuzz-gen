// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsGetProfileIOhandler at cmsio0.c:517:25 in lcms2.h
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// cmsOpenIOhandlerFromMem at cmsio0.c:238:25 in lcms2.h
// cmsSaveProfileToIOhandler at cmsio0.c:1447:27 in lcms2.h
// cmsOpenIOhandlerFromStream at cmsio0.c:477:25 in lcms2.h
// cmsOpenIOhandlerFromNULL at cmsio0.c:100:26 in lcms2.h
// cmsOpenIOhandlerFromMem at cmsio0.c:238:25 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

static void fuzz_cmsGetProfileIOhandler(cmsHPROFILE hProfile) {
    cmsIOHANDLER* handler = cmsGetProfileIOhandler(hProfile);
    if (handler != NULL) {
        handler->Close(handler);
    }
}

static void fuzz__cmsReadUInt32Number(cmsIOHANDLER* io) {
    cmsUInt32Number n;
    _cmsReadUInt32Number(io, &n);
}

static void fuzz_cmsOpenIOhandlerFromMem(cmsContext ContextID, const uint8_t *Data, size_t Size) {
    cmsIOHANDLER* handler = cmsOpenIOhandlerFromMem(ContextID, (void *)Data, (cmsUInt32Number)Size, "r");
    if (handler != NULL) {
        handler->Close(handler);
    }
}

static void fuzz_cmsSaveProfileToIOhandler(cmsHPROFILE hProfile, cmsIOHANDLER* io) {
    if (hProfile != NULL && io != NULL) {
        cmsSaveProfileToIOhandler(hProfile, io);
    }
}

static void fuzz_cmsOpenIOhandlerFromStream(cmsContext ContextID) {
    FILE* dummyFile = fopen("./dummy_file", "wb+");
    if (dummyFile != NULL) {
        cmsIOHANDLER* handler = cmsOpenIOhandlerFromStream(ContextID, dummyFile);
        if (handler != NULL) {
            handler->Close(handler);
        } else {
            fclose(dummyFile);
        }
    }
}

static void fuzz_cmsOpenIOhandlerFromNULL(cmsContext ContextID) {
    cmsIOHANDLER* handler = cmsOpenIOhandlerFromNULL(ContextID);
    if (handler != NULL) {
        handler->Close(handler);
    }
}

int LLVMFuzzerTestOneInput_142(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return 0;

    cmsContext dummyContext = NULL;
    cmsHPROFILE dummyProfile = NULL;

    // Fuzz each function with the provided data
    fuzz_cmsGetProfileIOhandler(dummyProfile);

    cmsIOHANDLER* memHandler = cmsOpenIOhandlerFromMem(dummyContext, (void *)Data, (cmsUInt32Number)Size, "r");
    if (memHandler != NULL) {
        fuzz__cmsReadUInt32Number(memHandler);
        fuzz_cmsSaveProfileToIOhandler(dummyProfile, memHandler);
        memHandler->Close(memHandler);
    }

    fuzz_cmsOpenIOhandlerFromStream(dummyContext);
    fuzz_cmsOpenIOhandlerFromNULL(dummyContext);

    return 0;
}