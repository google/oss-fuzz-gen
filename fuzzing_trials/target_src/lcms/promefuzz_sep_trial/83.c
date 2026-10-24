// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSetColorSpace at cmsio0.c:1088:16 in lcms2.h
// cmsSetPCS at cmsio0.c:1076:16 in lcms2.h
// cmsChannelsOf at cmspcs.c:945:27 in lcms2.h
// _cmsLCMScolorSpace at cmspcs.c:810:15 in lcms2.h
// cmsChannelsOfColorSpace at cmspcs.c:877:26 in lcms2.h
// _cmsICCcolorSpace at cmspcs.c:764:34 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "lcms2.h"

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile for testing
    return cmsCreate_sRGBProfile();
}

static void destroyDummyProfile(cmsHPROFILE hProfile) {
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }
}

int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    cmsHPROFILE hProfile = createDummyProfile();
    if (hProfile == NULL) {
        return 0;
    }

    cmsColorSpaceSignature sig = *(const cmsColorSpaceSignature *)Data;
    cmsColorSpaceSignature pcs = *(const cmsColorSpaceSignature *)Data;

    // Fuzz cmsSetColorSpace
    cmsSetColorSpace(hProfile, sig);

    // Fuzz cmsSetPCS
    cmsSetPCS(hProfile, pcs);

    // Fuzz cmsChannelsOf
    cmsUInt32Number channels = cmsChannelsOf(sig);

    // Fuzz _cmsLCMScolorSpace
    int lcmsColorSpace = _cmsLCMScolorSpace(sig);

    // Fuzz cmsChannelsOfColorSpace
    cmsInt32Number channelsOfColorSpace = cmsChannelsOfColorSpace(sig);

    // Fuzz _cmsICCcolorSpace
    cmsColorSpaceSignature iccColorSpace = _cmsICCcolorSpace(lcmsColorSpace);

    // Cleanup
    destroyDummyProfile(hProfile);

    return 0;
}