// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromMem at cmsio0.c:1296:23 in lcms2.h
// cmsGetProfileIOhandler at cmsio0.c:517:25 in lcms2.h
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// cmsOpenIOhandlerFromMem at cmsio0.c:238:25 in lcms2.h
// cmsSaveProfileToIOhandler at cmsio0.c:1447:27 in lcms2.h
// cmsOpenIOhandlerFromStream at cmsio0.c:477:25 in lcms2.h
// cmsSaveProfileToIOhandler at cmsio0.c:1447:27 in lcms2.h
// cmsOpenIOhandlerFromNULL at cmsio0.c:100:26 in lcms2.h
// cmsSaveProfileToIOhandler at cmsio0.c:1447:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>
#include <lcms2_plugin.h>

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile using a memory buffer
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(NULL, 0);
    return hProfile;
}

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_161(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy profile
    cmsHPROFILE hProfile = createDummyProfile();
    if (!hProfile) return 0;

    // Get IO handler from the profile
    cmsIOHANDLER *ioHandler = cmsGetProfileIOhandler(hProfile);
    if (ioHandler) {
        // Attempt to read a UInt32 number from the IO handler
        cmsUInt32Number number;
        _cmsReadUInt32Number(ioHandler, &number);
    }

    // Open IO handler from memory
    cmsIOHANDLER *memHandler = cmsOpenIOhandlerFromMem(NULL, (void *)Data, (cmsUInt32Number)Size, "r");
    if (memHandler) {
        cmsUInt32Number usedSpace = cmsSaveProfileToIOhandler(hProfile, memHandler);
        (void)usedSpace; // Suppress unused variable warning

        // Clean up
        if (memHandler->Close)
            memHandler->Close(memHandler);
    }

    // Open a dummy file and create an IO handler from it
    writeDummyFile(Data, Size);
    FILE *file = fopen("./dummy_file", "rb");
    if (file) {
        cmsIOHANDLER *streamHandler = cmsOpenIOhandlerFromStream(NULL, file);
        if (streamHandler) {
            cmsUInt32Number usedSpace = cmsSaveProfileToIOhandler(hProfile, streamHandler);
            (void)usedSpace; // Suppress unused variable warning

            // Clean up
            if (streamHandler->Close)
                streamHandler->Close(streamHandler);
        }
        fclose(file);
    }

    // Create a NULL IO handler
    cmsIOHANDLER *nullHandler = cmsOpenIOhandlerFromNULL(NULL);
    if (nullHandler) {
        cmsUInt32Number usedSpace = cmsSaveProfileToIOhandler(hProfile, nullHandler);
        (void)usedSpace; // Suppress unused variable warning

        // Clean up
        if (nullHandler->Close)
            nullHandler->Close(nullHandler);
    }

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}