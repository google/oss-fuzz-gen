// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreateContext at cmsplugin.c:824:22 in lcms2.h
// cmsSetAlarmCodesTHR at cmsxform.c:93:16 in lcms2.h
// cmsCreate_sRGBProfileTHR at cmsvirt.c:653:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateXYZProfileTHR at cmsvirt.c:577:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsOpenProfileFromFileTHR at cmsio0.c:1204:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateDeviceLinkFromCubeFileTHR at cmscgats.c:3211:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSignalError at cmserr.c:510:16 in lcms2_plugin.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
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

#define DUMMY_FILE "./dummy_file"
#define MAX_ALARM_CODES cmsMAXCHANNELS

static cmsContext createDummyContext() {
    return cmsCreateContext(NULL, NULL);
}

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *f = fopen(DUMMY_FILE, "wb");
    if (f) {
        fwrite(Data, 1, Size, f);
        fclose(f);
    }
}

int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number) * MAX_ALARM_CODES + 2) {
        return 0;
    }

    cmsContext context = createDummyContext();
    if (!context) {
        return 0;
    }

    cmsUInt16Number alarmCodes[MAX_ALARM_CODES];
    memcpy(alarmCodes, Data, sizeof(cmsUInt16Number) * MAX_ALARM_CODES);

    cmsSetAlarmCodesTHR(context, alarmCodes);

    cmsHPROFILE sRGBProfile = cmsCreate_sRGBProfileTHR(context);
    if (sRGBProfile) {
        cmsCloseProfile(sRGBProfile);
    }

    cmsHPROFILE xyzProfile = cmsCreateXYZProfileTHR(context);
    if (xyzProfile) {
        cmsCloseProfile(xyzProfile);
    }

    writeDummyFile(Data + sizeof(cmsUInt16Number) * MAX_ALARM_CODES, Size - sizeof(cmsUInt16Number) * MAX_ALARM_CODES);
    cmsHPROFILE fileProfile = cmsOpenProfileFromFileTHR(context, DUMMY_FILE, "r");
    if (fileProfile) {
        cmsCloseProfile(fileProfile);
    }

    cmsHPROFILE cubeProfile = cmsCreateDeviceLinkFromCubeFileTHR(context, DUMMY_FILE);
    if (cubeProfile) {
        cmsCloseProfile(cubeProfile);
    }

    cmsSignalError(context, *(cmsUInt32Number *)(Data + Size - 4), "Fuzzing error test");

    cmsDeleteContext(context);

    return 0;
}