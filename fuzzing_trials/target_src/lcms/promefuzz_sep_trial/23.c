// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsReverseToneCurveEx at cmsgamma.c:1070:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsJoinToneCurve at cmsgamma.c:980:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsReverseToneCurve at cmsgamma.c:1137:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsDupToneCurve at cmsgamma.c:968:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsDupToneCurve at cmsgamma.c:968:25 in lcms2.h
// cmsDupToneCurve at cmsgamma.c:968:25 in lcms2.h
// cmsFreeToneCurveTriple at cmsgamma.c:954:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

static cmsToneCurve* create_dummy_tone_curve(cmsUInt32Number nEntries) {
    cmsToneCurve* curve = cmsBuildGamma(NULL, 1.0);
    if (!curve) return NULL;
    // Assume nEntries is valid and compatible with the curve
    return curve;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return 0;

    cmsUInt32Number nEntries = *(cmsUInt32Number*)Data;
    cmsToneCurve* curve1 = create_dummy_tone_curve(nEntries);
    cmsToneCurve* curve2 = create_dummy_tone_curve(nEntries);

    if (!curve1 || !curve2) {
        cmsFreeToneCurve(curve1);
        cmsFreeToneCurve(curve2);
        return 0;
    }

    // Test cmsReverseToneCurveEx
    cmsToneCurve* reversedCurveEx = cmsReverseToneCurveEx(nEntries, curve1);
    if (reversedCurveEx) cmsFreeToneCurve(reversedCurveEx);

    // Test cmsJoinToneCurve
    cmsToneCurve* joinedCurve = cmsJoinToneCurve(NULL, curve1, curve2, nEntries);
    if (joinedCurve) cmsFreeToneCurve(joinedCurve);

    // Test cmsReverseToneCurve
    cmsToneCurve* reversedCurve = cmsReverseToneCurve(curve1);
    if (reversedCurve) cmsFreeToneCurve(reversedCurve);

    // Test cmsDupToneCurve
    cmsToneCurve* dupedCurve = cmsDupToneCurve(curve1);
    if (dupedCurve) cmsFreeToneCurve(dupedCurve);

    // Ensure we do not use after free
    cmsToneCurve* triple[3] = {cmsDupToneCurve(curve1), cmsDupToneCurve(curve2), NULL};
    cmsFreeToneCurveTriple(triple);

    cmsFreeToneCurve(curve1);
    cmsFreeToneCurve(curve2);

    return 0;
}