// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsSetColorSpace at cmsio0.c:1088:16 in lcms2.h
// cmsSetPCS at cmsio0.c:1076:16 in lcms2.h
// cmsGetPCS at cmsio0.c:1070:34 in lcms2.h
// cmsGetColorSpace at cmsio0.c:1082:34 in lcms2.h
// _cmsLCMScolorSpace at cmspcs.c:810:15 in lcms2.h
// _cmsICCcolorSpace at cmspcs.c:764:34 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

static cmsHPROFILE createDummyProfile() {
    return cmsCreate_sRGBProfile();
}

int LLVMFuzzerTestOneInput_123(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsColorSpaceSignature)) return 0;

    cmsHPROFILE hProfile = createDummyProfile();
    if (!hProfile) return 0;

    cmsColorSpaceSignature sig = *(cmsColorSpaceSignature*)Data;

    // Fuzz cmsSetColorSpace
    cmsSetColorSpace(hProfile, sig);

    // Fuzz cmsSetPCS
    cmsSetPCS(hProfile, sig);

    // Fuzz cmsGetPCS
    cmsColorSpaceSignature pcs = cmsGetPCS(hProfile);

    // Fuzz cmsGetColorSpace
    cmsColorSpaceSignature colorSpace = cmsGetColorSpace(hProfile);

    // Fuzz _cmsLCMScolorSpace
    int lcmsColorSpace = _cmsLCMScolorSpace(sig);

    // Fuzz _cmsICCcolorSpace
    cmsColorSpaceSignature iccColorSpace = _cmsICCcolorSpace(lcmsColorSpace);

    // Cleanup
    cmsCloseProfile(hProfile);

    return 0;
}