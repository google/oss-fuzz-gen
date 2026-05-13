// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurve16 at cmsgamma.c:783:25 in lcms2.h
// cmsGetToneCurveEstimatedTable at cmsgamma.c:774:34 in lcms2.h
// cmsReverseToneCurve at cmsgamma.c:1137:25 in lcms2.h
// cmsEvalToneCurve16 at cmsgamma.c:1437:27 in lcms2.h
// cmsDupToneCurve at cmsgamma.c:968:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurveTriple at cmsgamma.c:954:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "lcms2.h"

static cmsToneCurve* createToneCurve(cmsContext context, size_t size, const uint8_t *data) {
    if (size < sizeof(cmsUInt16Number)) return NULL;

    cmsUInt32Number nEntries = size / sizeof(cmsUInt16Number);
    if (nEntries == 0) return NULL;

    cmsUInt16Number* values = (cmsUInt16Number*)data;
    return cmsBuildTabulatedToneCurve16(context, nEntries, values);
}

int LLVMFuzzerTestOneInput_92(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number)) return 0;

    cmsContext context = NULL; // Using a NULL context for simplicity
    cmsToneCurve* curve = createToneCurve(context, Size, Data);
    if (!curve) return 0;

    // Test cmsGetToneCurveEstimatedTable
    const cmsUInt16Number* estimatedTable = cmsGetToneCurveEstimatedTable(curve);
    if (estimatedTable != NULL) {
        // Do something with estimatedTable, if needed
    }

    // Test cmsReverseToneCurve
    cmsToneCurve* reversedCurve = cmsReverseToneCurve(curve);
    if (reversedCurve) {
        // Test cmsEvalToneCurve16
        cmsUInt16Number input = 12345; // Example input value
        cmsEvalToneCurve16(reversedCurve, input);

        // Test cmsDupToneCurve
        cmsToneCurve* duplicatedCurve = cmsDupToneCurve(reversedCurve);
        if (duplicatedCurve) {
            cmsFreeToneCurve(duplicatedCurve);
        }

        cmsFreeToneCurve(reversedCurve);
    }

    // Prepare a dummy array for cmsFreeToneCurveTriple
    cmsToneCurve* triple[3] = {curve, NULL, NULL};
    cmsFreeToneCurveTriple(triple);

    return 0;
}