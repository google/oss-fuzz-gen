// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsSetHeaderFlags at cmsio0.c:1003:16 in lcms2.h
// cmsGetHeaderRenderingIntent at cmsio0.c:985:27 in lcms2.h
// cmsSetHeaderManufacturer at cmsio0.c:1015:16 in lcms2.h
// cmsGetEncodedICCversion at cmsio0.c:1106:27 in lcms2.h
// cmsGetHeaderProfileID at cmsio0.c:1051:16 in lcms2.h
// cmsSetHeaderProfileID at cmsio0.c:1057:16 in lcms2.h
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
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

static void fuzz_cmsSetHeaderFlags(cmsHPROFILE hProfile, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return;
    cmsUInt32Number Flags = *(cmsUInt32Number*)Data;
    cmsSetHeaderFlags(hProfile, Flags);
}

static void fuzz_cmsGetHeaderRenderingIntent(cmsHPROFILE hProfile) {
    cmsUInt32Number intent = cmsGetHeaderRenderingIntent(hProfile);
    (void)intent; // Suppress unused variable warning
}

static void fuzz_cmsSetHeaderManufacturer(cmsHPROFILE hProfile, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return;
    cmsUInt32Number manufacturer = *(cmsUInt32Number*)Data;
    cmsSetHeaderManufacturer(hProfile, manufacturer);
}

static void fuzz_cmsGetEncodedICCversion(cmsHPROFILE hProfile) {
    cmsUInt32Number version = cmsGetEncodedICCversion(hProfile);
    (void)version; // Suppress unused variable warning
}

static void fuzz_cmsGetHeaderProfileID(cmsHPROFILE hProfile) {
    cmsUInt8Number ProfileID[16];
    cmsGetHeaderProfileID(hProfile, ProfileID);
}

static void fuzz_cmsSetHeaderProfileID(cmsHPROFILE hProfile, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    cmsSetHeaderProfileID(hProfile, (cmsUInt8Number*)Data);
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        FILE *file = fopen("./dummy_file", "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
        }
    }

    if (hProfile) {
        fuzz_cmsSetHeaderFlags(hProfile, Data, Size);
        fuzz_cmsGetHeaderRenderingIntent(hProfile);
        fuzz_cmsSetHeaderManufacturer(hProfile, Data, Size);
        fuzz_cmsGetEncodedICCversion(hProfile);
        fuzz_cmsGetHeaderProfileID(hProfile);
        fuzz_cmsSetHeaderProfileID(hProfile, Data, Size);
        cmsCloseProfile(hProfile);
    }

    return 0;
}