// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurve16 at cmsgamma.c:783:25 in lcms2.h
// cmsIsToneCurveDescending at cmsgamma.c:1393:20 in lcms2.h
// cmsIsToneCurveMultisegment at cmsgamma.c:1402:20 in lcms2.h
// cmsGetToneCurveParametricType at cmsgamma.c:1409:27 in lcms2.h
// cmsIsToneCurveMonotonic at cmsgamma.c:1347:20 in lcms2.h
// cmsIsToneCurveLinear at cmsgamma.c:1329:19 in lcms2.h
// cmsGetToneCurveParametricType at cmsgamma.c:1409:27 in lcms2.h
// cmsGetToneCurveSegment at cmsgamma.c:1507:34 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

static cmsToneCurve* createToneCurveFromData(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return NULL;

    cmsUInt32Number nEntries = *(cmsUInt32Number*)Data;
    if (nEntries == 0 || nEntries > (Size - sizeof(cmsUInt32Number)) / sizeof(cmsUInt16Number)) return NULL;

    cmsUInt16Number* table = (cmsUInt16Number*)malloc(nEntries * sizeof(cmsUInt16Number));
    if (!table) return NULL;

    memcpy(table, Data + sizeof(cmsUInt32Number), nEntries * sizeof(cmsUInt16Number));

    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(NULL, nEntries, table);
    free(table);
    return curve;
}

int LLVMFuzzerTestOneInput_98(const uint8_t *Data, size_t Size) {
    cmsToneCurve* toneCurve = createToneCurveFromData(Data, Size);
    if (!toneCurve) return 0;

    cmsBool isDescending = cmsIsToneCurveDescending(toneCurve);
    cmsBool isMultisegment = cmsIsToneCurveMultisegment(toneCurve);
    cmsInt32Number parametricType = cmsGetToneCurveParametricType(toneCurve);
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);
    cmsBool isLinear = cmsIsToneCurveLinear(toneCurve);

    cmsInt32Number nSegments = cmsGetToneCurveParametricType(toneCurve) == 0 ? 0 : 1;
    for (cmsInt32Number i = 0; i < nSegments; i++) {
        const cmsCurveSegment* segment = cmsGetToneCurveSegment(i, toneCurve);
    }

    cmsFreeToneCurve(toneCurve);
    return 0;
}