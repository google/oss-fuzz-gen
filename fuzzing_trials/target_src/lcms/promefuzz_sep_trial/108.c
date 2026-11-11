// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurveFloat at cmsgamma.c:832:25 in lcms2.h
// cmsReverseToneCurveEx at cmsgamma.c:1070:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsReverseToneCurve at cmsgamma.c:1137:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsEvalToneCurveFloat at cmsgamma.c:1418:28 in lcms2.h
// cmsDupToneCurve at cmsgamma.c:968:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurveTriple at cmsgamma.c:954:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

static cmsToneCurve* createRandomToneCurve(cmsUInt32Number nEntries, const uint8_t *Data, size_t Size) {
    cmsFloat32Number *values = (cmsFloat32Number*) malloc(nEntries * sizeof(cmsFloat32Number));
    if (!values) return NULL;

    for (cmsUInt32Number i = 0; i < nEntries; i++) {
        values[i] = (cmsFloat32Number) (Data[i % Size] / 255.0);
    }

    cmsToneCurve* curve = cmsBuildTabulatedToneCurveFloat(NULL, nEntries, values);
    free(values);
    return curve;
}

int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Not enough data to proceed

    cmsUInt32Number nEntries = Data[0] % 256 + 1; // Ensure at least one entry
    cmsToneCurve* toneCurve = createRandomToneCurve(nEntries, Data, Size);
    if (!toneCurve) return 0;

    cmsToneCurve* reversedCurveEx = cmsReverseToneCurveEx(nEntries, toneCurve);
    if (reversedCurveEx) {
        cmsFreeToneCurve(reversedCurveEx);
    }

    cmsToneCurve* reversedCurve = cmsReverseToneCurve(toneCurve);
    if (reversedCurve) {
        cmsFreeToneCurve(reversedCurve);
    }

    cmsFloat32Number evalValue = (cmsFloat32Number) (Data[0] / 255.0);
    cmsEvalToneCurveFloat(toneCurve, evalValue);

    cmsToneCurve* duplicatedCurve = cmsDupToneCurve(toneCurve);
    if (duplicatedCurve) {
        cmsFreeToneCurve(duplicatedCurve);
    }

    cmsFreeToneCurve(toneCurve);

    // Test cmsFreeToneCurveTriple with a dummy triple
    cmsToneCurve* triple[3] = {NULL, NULL, NULL};
    triple[0] = createRandomToneCurve(nEntries, Data, Size);
    triple[1] = createRandomToneCurve(nEntries, Data, Size);
    triple[2] = createRandomToneCurve(nEntries, Data, Size);

    cmsFreeToneCurveTriple(triple);

    return 0;
}