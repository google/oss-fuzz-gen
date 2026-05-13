// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsGetProfileIOhandler at cmsio0.c:517:25 in lcms2.h
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// cmsOpenIOhandlerFromMem at cmsio0.c:238:25 in lcms2.h
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// cmsSaveProfileToIOhandler at cmsio0.c:1447:27 in lcms2.h
// cmsOpenIOhandlerFromStream at cmsio0.c:477:25 in lcms2.h
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// cmsOpenIOhandlerFromNULL at cmsio0.c:100:26 in lcms2.h
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

static cmsHPROFILE CreateDummyProfile() {
    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        FILE *f = fopen("./dummy_file", "wb");
        if (f) {
            // Write some dummy data to create a valid ICC profile
            const char dummyData[128] = {0};
            fwrite(dummyData, 1, sizeof(dummyData), f);
            fclose(f);
            hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
        }
    }
    return hProfile;
}

int LLVMFuzzerTestOneInput_152(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    // Create a dummy profile
    cmsHPROFILE hProfile = CreateDummyProfile();
    if (!hProfile) return 0;

    // Test cmsGetProfileIOhandler
    cmsIOHANDLER* ioHandler = cmsGetProfileIOhandler(hProfile);
    if (ioHandler) {
        cmsUInt32Number value;
        _cmsReadUInt32Number(ioHandler, &value);
    }

    // Test cmsOpenIOhandlerFromMem
    cmsIOHANDLER* memHandler = cmsOpenIOhandlerFromMem(NULL, (void*)Data, (cmsUInt32Number)Size, "r");
    if (memHandler) {
        cmsUInt32Number value;
        _cmsReadUInt32Number(memHandler, &value);
    }

    // Test cmsSaveProfileToIOhandler
    if (ioHandler) {
        cmsSaveProfileToIOhandler(hProfile, ioHandler);
    }

    // Test cmsOpenIOhandlerFromStream
    FILE *stream = fopen("./dummy_file", "rb");
    if (stream) {
        cmsIOHANDLER* streamHandler = cmsOpenIOhandlerFromStream(NULL, stream);
        if (streamHandler) {
            cmsUInt32Number value;
            _cmsReadUInt32Number(streamHandler, &value);
        }
        fclose(stream);
    }

    // Test cmsOpenIOhandlerFromNULL
    cmsIOHANDLER* nullHandler = cmsOpenIOhandlerFromNULL(NULL);
    if (nullHandler) {
        cmsUInt32Number value;
        _cmsReadUInt32Number(nullHandler, &value);
    }

    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}