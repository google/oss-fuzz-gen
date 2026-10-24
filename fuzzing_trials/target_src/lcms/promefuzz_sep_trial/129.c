// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsCreateRGBProfile at cmsvirt.c:217:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsFreeToneCurveTriple at cmsgamma.c:954:16 in lcms2.h
// cmsBuildParametricToneCurve at cmsgamma.c:880:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsCreateGrayProfile at cmsvirt.c:280:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

static cmsCIExyY D65WhitePoint = {0.3127, 0.3290, 1.0};
static cmsCIExyYTRIPLE Rec709Primaries = {
    {0.64, 0.33, 0.03},  // Red
    {0.30, 0.60, 0.10},  // Green
    {0.15, 0.06, 0.79}   // Blue
};

static void fuzz_cmsCreateRGBProfile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) * 3) return;

    cmsFloat64Number gammaValues[3];
    for (int i = 0; i < 3; i++) {
        gammaValues[i] = ((cmsFloat64Number *)Data)[i];
    }

    cmsToneCurve *transferFunctions[3];
    for (int i = 0; i < 3; i++) {
        transferFunctions[i] = cmsBuildGamma(NULL, gammaValues[i]);
    }

    cmsHPROFILE hProfile = cmsCreateRGBProfile(&D65WhitePoint, &Rec709Primaries, transferFunctions);
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    cmsFreeToneCurveTriple(transferFunctions);
}

static void fuzz_cmsBuildParametricToneCurve(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) * 10) return;

    cmsFloat64Number params[10];
    for (int i = 0; i < 10; i++) {
        params[i] = ((cmsFloat64Number *)Data)[i];
    }

    cmsToneCurve *toneCurve = cmsBuildParametricToneCurve(NULL, *(cmsInt32Number *)Data, params);
    if (toneCurve) {
        cmsFreeToneCurve(toneCurve);
    }
}

static void fuzz_cmsCreateGrayProfile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsToneCurve *transferFunction = cmsBuildGamma(NULL, *(cmsFloat64Number *)Data);
    cmsHPROFILE hProfile = cmsCreateGrayProfile(&D65WhitePoint, transferFunction);

    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    if (transferFunction) {
        cmsFreeToneCurve(transferFunction);
    }
}

int LLVMFuzzerTestOneInput_129(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateRGBProfile(Data, Size);
    fuzz_cmsBuildParametricToneCurve(Data, Size);
    fuzz_cmsCreateGrayProfile(Data, Size);
    return 0;
}