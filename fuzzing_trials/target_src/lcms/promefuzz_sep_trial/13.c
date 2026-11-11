// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsCreateRGBProfile at cmsvirt.c:217:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateLab2ProfileTHR at cmsvirt.c:473:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateGrayProfileTHR at cmsvirt.c:227:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateLab4Profile at cmsvirt.c:570:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateRGBProfileTHR at cmsvirt.c:101:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreate_OkLabProfile at cmsvirt.c:690:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsCIExyY* createRandomCIExyY(const uint8_t** Data, size_t* Size) {
    if (*Size < sizeof(cmsCIExyY)) return NULL;
    cmsCIExyY* xyY = (cmsCIExyY*)malloc(sizeof(cmsCIExyY));
    memcpy(xyY, *Data, sizeof(cmsCIExyY));
    *Data += sizeof(cmsCIExyY);
    *Size -= sizeof(cmsCIExyY);
    return xyY;
}

static cmsCIExyYTRIPLE* createRandomCIExyYTRIPLE(const uint8_t** Data, size_t* Size) {
    if (*Size < sizeof(cmsCIExyYTRIPLE)) return NULL;
    cmsCIExyYTRIPLE* triple = (cmsCIExyYTRIPLE*)malloc(sizeof(cmsCIExyYTRIPLE));
    memcpy(triple, *Data, sizeof(cmsCIExyYTRIPLE));
    *Data += sizeof(cmsCIExyYTRIPLE);
    *Size -= sizeof(cmsCIExyYTRIPLE);
    return triple;
}

static cmsToneCurve* createRandomToneCurve() {
    // Create a simple tone curve with one segment
    cmsToneCurve* curve = cmsBuildGamma(NULL, 1.0);
    return curve;
}

static cmsToneCurve** createRandomToneCurveArray() {
    cmsToneCurve** curves = (cmsToneCurve**)malloc(3 * sizeof(cmsToneCurve*));
    for (int i = 0; i < 3; i++) {
        curves[i] = createRandomToneCurve();
        if (curves[i] == NULL) {
            for (int j = 0; j < i; j++) cmsFreeToneCurve(curves[j]);
            free(curves);
            return NULL;
        }
    }
    return curves;
}

static void freeToneCurveArray(cmsToneCurve** curves) {
    for (int i = 0; i < 3; i++) {
        cmsFreeToneCurve(curves[i]);
    }
    free(curves);
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    cmsContext context = NULL;

    // Create random white point, primaries and tone curves
    cmsCIExyY* whitePoint = createRandomCIExyY(&Data, &Size);
    cmsCIExyYTRIPLE* primaries = createRandomCIExyYTRIPLE(&Data, &Size);
    cmsToneCurve** transferFunction = createRandomToneCurveArray();

    if (whitePoint && primaries && transferFunction) {
        // Fuzz cmsCreateRGBProfile
        cmsHPROFILE profileRGB = cmsCreateRGBProfile(whitePoint, primaries, transferFunction);
        if (profileRGB) cmsCloseProfile(profileRGB);

        // Fuzz cmsCreateLab2ProfileTHR
        cmsHPROFILE profileLab2 = cmsCreateLab2ProfileTHR(context, whitePoint);
        if (profileLab2) cmsCloseProfile(profileLab2);

        // Fuzz cmsCreateGrayProfileTHR
        cmsHPROFILE profileGray = cmsCreateGrayProfileTHR(context, whitePoint, transferFunction[0]);
        if (profileGray) cmsCloseProfile(profileGray);

        // Fuzz cmsCreateLab4Profile
        cmsHPROFILE profileLab4 = cmsCreateLab4Profile(whitePoint);
        if (profileLab4) cmsCloseProfile(profileLab4);

        // Fuzz cmsCreateRGBProfileTHR
        cmsHPROFILE profileRGBTHR = cmsCreateRGBProfileTHR(context, whitePoint, primaries, transferFunction);
        if (profileRGBTHR) cmsCloseProfile(profileRGBTHR);

        // Fuzz cmsCreate_OkLabProfile
        cmsHPROFILE profileOkLab = cmsCreate_OkLabProfile(context);
        if (profileOkLab) cmsCloseProfile(profileOkLab);
    }

    // Free allocated resources
    free(whitePoint);
    free(primaries);
    if (transferFunction) freeToneCurveArray(transferFunction);

    return 0;
}