// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsEstimateGamma at cmsgamma.c:1465:28 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsSmoothToneCurve at cmsgamma.c:1213:20 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsDetectRGBProfileGamma at cmsgmt.c:605:28 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsBuildParametricToneCurve at cmsgamma.c:880:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsIsToneCurveLinear at cmsgamma.c:1329:19 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <lcms2.h>

static void fuzz_cmsEstimateGamma(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsFloat64Number precision = *((cmsFloat64Number*)Data);
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value for testing

    if (toneCurve) {
        cmsEstimateGamma(toneCurve, precision);
        cmsFreeToneCurve(toneCurve);
    }
}

static void fuzz_cmsSmoothToneCurve(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsFloat64Number lambda = *((cmsFloat64Number*)Data);
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value for testing

    if (toneCurve) {
        cmsSmoothToneCurve(toneCurve, lambda);
        cmsFreeToneCurve(toneCurve);
    }
}

static void fuzz_cmsBuildGamma(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsFloat64Number gamma = *((cmsFloat64Number*)Data);
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, gamma);

    if (toneCurve) {
        cmsFreeToneCurve(toneCurve);
    }
}

static void fuzz_cmsDetectRGBProfileGamma(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsFloat64Number threshold = *((cmsFloat64Number*)Data);

    FILE *f = fopen("./dummy_file", "wb");
    if (!f) return;
    fwrite(Data + sizeof(cmsFloat64Number), 1, Size - sizeof(cmsFloat64Number), f);
    fclose(f);

    cmsHPROFILE profile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (profile) {
        cmsDetectRGBProfileGamma(profile, threshold);
        cmsCloseProfile(profile);
    }
}

static void fuzz_cmsBuildParametricToneCurve(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsInt32Number) + sizeof(cmsFloat64Number)) return;

    cmsInt32Number type = *((cmsInt32Number*)Data);
    const cmsFloat64Number* params = (const cmsFloat64Number*)(Data + sizeof(cmsInt32Number));

    cmsToneCurve* toneCurve = cmsBuildParametricToneCurve(NULL, type, params);

    if (toneCurve) {
        cmsFreeToneCurve(toneCurve);
    }
}

static void fuzz_cmsIsToneCurveLinear(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value for testing

    if (toneCurve) {
        cmsIsToneCurveLinear(toneCurve);
        cmsFreeToneCurve(toneCurve);
    }
}

int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size) {
    fuzz_cmsEstimateGamma(Data, Size);
    fuzz_cmsSmoothToneCurve(Data, Size);
    fuzz_cmsBuildGamma(Data, Size);
    fuzz_cmsDetectRGBProfileGamma(Data, Size);
    fuzz_cmsBuildParametricToneCurve(Data, Size);
    fuzz_cmsIsToneCurveLinear(Data, Size);

    return 0;
}