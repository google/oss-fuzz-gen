// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsGetHeaderCreationDateTime at cmsio0.c:1063:20 in lcms2.h
// _cmsAdjustEndianess64 at cmsplugin.c:79:17 in lcms2_plugin.h
// _cmsReadUInt64Number at cmsplugin.c:206:21 in lcms2_plugin.h
// _cmsEncodeDateTimeNumber at cmsplugin.c:407:16 in lcms2_plugin.h
// _cmsDecodeDateTimeNumber at cmsplugin.c:390:16 in lcms2_plugin.h
// cmsGetHeaderAttributes at cmsio0.c:1039:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

static cmsHPROFILE create_dummy_profile() {
    // Create a dummy ICC profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (!hProfile) {
        fprintf(stderr, "Failed to create dummy ICC profile\n");
        exit(1);
    }
    return hProfile;
}

static cmsUInt32Number dummy_read(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    return size * count;
}

int LLVMFuzzerTestOneInput_150(const uint8_t *Data, size_t Size) {
    // Prepare environment for cmsGetHeaderCreationDateTime
    cmsHPROFILE hProfile = create_dummy_profile();
    struct tm creationTime;
    cmsGetHeaderCreationDateTime(hProfile, &creationTime);

    // Prepare environment for _cmsAdjustEndianess64
    cmsUInt64Number input64 = 0;
    cmsUInt64Number output64 = 0;
    if (Size >= sizeof(cmsUInt64Number)) {
        memcpy(&input64, Data, sizeof(cmsUInt64Number));
        _cmsAdjustEndianess64(&output64, &input64);
    }

    // Prepare environment for _cmsReadUInt64Number
    cmsIOHANDLER ioHandler;
    memset(&ioHandler, 0, sizeof(ioHandler));
    ioHandler.Read = dummy_read;
    cmsUInt64Number read64;
    _cmsReadUInt64Number(&ioHandler, &read64);

    // Prepare environment for _cmsEncodeDateTimeNumber
    cmsDateTimeNumber encodedTime;
    _cmsEncodeDateTimeNumber(&encodedTime, &creationTime);

    // Prepare environment for _cmsDecodeDateTimeNumber
    struct tm decodedTime;
    _cmsDecodeDateTimeNumber(&encodedTime, &decodedTime);

    // Prepare environment for cmsGetHeaderAttributes
    cmsUInt64Number flags;
    cmsGetHeaderAttributes(hProfile, &flags);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}