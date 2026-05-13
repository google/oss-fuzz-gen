// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurve16 at cmsgamma.c:783:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsIsToneCurveDescending at cmsgamma.c:1393:20 in lcms2.h
// cmsIsToneCurveMultisegment at cmsgamma.c:1402:20 in lcms2.h
// cmsGetToneCurveParametricType at cmsgamma.c:1409:27 in lcms2.h
// cmsIsToneCurveMonotonic at cmsgamma.c:1347:20 in lcms2.h
// cmsGetToneCurveSegment at cmsgamma.c:1507:34 in lcms2.h
// cmsIsToneCurveLinear at cmsgamma.c:1329:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "lcms2.h"

static cmsToneCurve* CreateToneCurveFromData(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 2) {
        return NULL;
    }

    cmsUInt32Number nEntries = *(cmsUInt32Number*)Data;
    Data += sizeof(cmsUInt32Number);
    Size -= sizeof(cmsUInt32Number);

    if (Size < nEntries * sizeof(cmsUInt16Number)) {
        return NULL;
    }

    cmsUInt16Number* Table16 = (cmsUInt16Number*)malloc(nEntries * sizeof(cmsUInt16Number));
    if (!Table16) {
        return NULL;
    }
    
    memcpy(Table16, Data, nEntries * sizeof(cmsUInt16Number));

    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(NULL, nEntries, Table16);
    free(Table16);

    return curve;
}

static void FreeToneCurve(cmsToneCurve* curve) {
    if (curve) {
        cmsFreeToneCurve(curve);
    }
}

int LLVMFuzzerTestOneInput_106(const uint8_t *Data, size_t Size) {
    cmsToneCurve* curve = CreateToneCurveFromData(Data, Size);
    if (!curve) {
        return 0;
    }

    // Test cmsIsToneCurveDescending
    cmsBool isDescending = cmsIsToneCurveDescending(curve);

    // Test cmsIsToneCurveMultisegment
    cmsBool isMultisegment = cmsIsToneCurveMultisegment(curve);

    // Test cmsGetToneCurveParametricType
    cmsInt32Number parametricType = cmsGetToneCurveParametricType(curve);

    // Test cmsIsToneCurveMonotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(curve);

    // Test cmsGetToneCurveSegment
    cmsInt32Number segmentIndex = 0; // Always test the first segment
    const cmsCurveSegment* segment = cmsGetToneCurveSegment(segmentIndex, curve);

    // Test cmsIsToneCurveLinear
    cmsBool isLinear = cmsIsToneCurveLinear(curve);

    FreeToneCurve(curve);
    return 0;
}