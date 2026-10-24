// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSetHeaderRenderingIntent at cmsio0.c:991:16 in lcms2.h
// cmsGetDeviceClass at cmsio0.c:1094:36 in lcms2.h
// cmsGetEncodedICCversion at cmsio0.c:1106:27 in lcms2.h
// cmsSetDeviceClass at cmsio0.c:1100:16 in lcms2.h
// cmsSetEncodedICCversion at cmsio0.c:1112:16 in lcms2.h
// cmsSetHeaderModel at cmsio0.c:1033:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

static cmsHPROFILE create_dummy_profile() {
    // Create a dummy ICC profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    return hProfile;
}

static void cleanup_profile(cmsHPROFILE hProfile) {
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }
}

int LLVMFuzzerTestOneInput_154(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    cmsHPROFILE hProfile = create_dummy_profile();
    if (hProfile == NULL) {
        return 0;
    }

    cmsUInt32Number value = *(cmsUInt32Number*)Data;
    cmsProfileClassSignature sig = (cmsProfileClassSignature)value;

    // Fuzz cmsSetHeaderRenderingIntent
    cmsSetHeaderRenderingIntent(hProfile, value);

    // Fuzz cmsGetDeviceClass
    cmsProfileClassSignature deviceClass = cmsGetDeviceClass(hProfile);

    // Fuzz cmsGetEncodedICCversion
    cmsUInt32Number iccVersion = cmsGetEncodedICCversion(hProfile);

    // Fuzz cmsSetDeviceClass
    cmsSetDeviceClass(hProfile, sig);

    // Fuzz cmsSetEncodedICCversion
    cmsSetEncodedICCversion(hProfile, value);

    // Fuzz cmsSetHeaderModel
    cmsSetHeaderModel(hProfile, value);

    cleanup_profile(hProfile);
    return 0;
}