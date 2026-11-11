// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsGetPostScriptCSA at cmsps2.c:1579:27 in lcms2.h
// _cmsMalloc at cmserr.c:265:17 in lcms2_plugin.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetPostScriptCSA at cmsps2.c:1579:27 in lcms2.h
// _cmsFree at cmserr.c:293:16 in lcms2_plugin.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 2) {
        return 0; // Not enough data to proceed
    }

    cmsContext context = NULL; // Use a null context
    cmsHPROFILE profile = cmsCreate_sRGBProfile();
    if (!profile) {
        return 0; // Failed to create profile
    }

    cmsUInt32Number intent = *(cmsUInt32Number *)Data;
    cmsUInt32Number flags = *(cmsUInt32Number *)(Data + sizeof(cmsUInt32Number));

    // First call to cmsGetPostScriptCSA
    cmsUInt32Number bufferLen = cmsGetPostScriptCSA(context, profile, intent, flags, NULL, 0);

    // Allocate memory using _cmsMalloc
    void *buffer = _cmsMalloc(context, bufferLen);
    if (!buffer) {
        cmsCloseProfile(profile);
        return 0; // Failed to allocate buffer
    }

    // Second call to cmsGetPostScriptCSA
    cmsUInt32Number written = cmsGetPostScriptCSA(context, profile, intent, flags, buffer, bufferLen);

    // Free allocated memory
    _cmsFree(context, buffer);
    cmsCloseProfile(profile);

    return 0;
}