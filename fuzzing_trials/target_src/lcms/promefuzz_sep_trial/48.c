// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurve16 at cmsgamma.c:783:25 in lcms2.h
// cmsSmoothToneCurve at cmsgamma.c:1213:20 in lcms2.h
// cmsIsToneCurveDescending at cmsgamma.c:1393:20 in lcms2.h
// cmsIsToneCurveMonotonic at cmsgamma.c:1347:20 in lcms2.h
// cmsIsToneCurveLinear at cmsgamma.c:1329:19 in lcms2.h
// cmsBuildParametricToneCurve at cmsgamma.c:880:25 in lcms2.h
// cmsGetToneCurveParametricType at cmsgamma.c:1409:27 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cmsToneCurve* createRandomToneCurve(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) + sizeof(cmsUInt16Number)) {
        return NULL;
    }

    cmsUInt32Number nEntries = *(cmsUInt32Number*)Data;
    nEntries = nEntries % 4096 + 1; // Limit to a reasonable number of entries
    Data += sizeof(cmsUInt32Number);
    Size -= sizeof(cmsUInt32Number);

    cmsUInt16Number* table = (cmsUInt16Number*)malloc(nEntries * sizeof(cmsUInt16Number));
    if (!table) {
        return NULL;
    }

    for (cmsUInt32Number i = 0; i < nEntries && Size >= sizeof(cmsUInt16Number); i++) {
        table[i] = *(cmsUInt16Number*)Data;
        Data += sizeof(cmsUInt16Number);
        Size -= sizeof(cmsUInt16Number);
    }

    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(NULL, nEntries, table);
    free(table);
    return curve;
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    cmsToneCurve* curve = createRandomToneCurve(Data, Size);
    if (!curve) {
        return 0;
    }

    cmsFloat64Number lambda = 0.5;
    cmsSmoothToneCurve(curve, lambda);

    cmsIsToneCurveDescending(curve);
    cmsIsToneCurveMonotonic(curve);
    cmsIsToneCurveLinear(curve);

    cmsContext context = NULL;
    cmsFloat64Number params[10] = {0};
    cmsToneCurve* parametricCurve = cmsBuildParametricToneCurve(context, 1, params);
    if (parametricCurve) {
        cmsGetToneCurveParametricType(parametricCurve);
        cmsFreeToneCurve(parametricCurve);
    }

    cmsFreeToneCurve(curve);
    return 0;
}