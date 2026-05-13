// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurve16 at cmsgamma.c:783:25 in lcms2.h
// cmsBuildTabulatedToneCurveFloat at cmsgamma.c:832:25 in lcms2.h
// cmsBuildSegmentedToneCurve at cmsgamma.c:797:25 in lcms2.h
// cmsJoinToneCurve at cmsgamma.c:980:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsReverseToneCurveEx at cmsgamma.c:1070:25 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsGetToneCurveEstimatedTableEntries at cmsgamma.c:768:27 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static cmsToneCurve* create_random_tone_curve16(cmsContext ContextID, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return NULL;
    cmsUInt32Number nEntries = *(cmsUInt32Number*)Data;
    if (nEntries == 0 || Size < sizeof(cmsUInt32Number) + nEntries * sizeof(cmsUInt16Number)) return NULL;
    const cmsUInt16Number *values = (const cmsUInt16Number*)(Data + sizeof(cmsUInt32Number));
    return cmsBuildTabulatedToneCurve16(ContextID, nEntries, values);
}

static cmsToneCurve* create_random_tone_curve_float(cmsContext ContextID, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return NULL;
    cmsUInt32Number nEntries = *(cmsUInt32Number*)Data;
    if (nEntries == 0 || Size < sizeof(cmsUInt32Number) + nEntries * sizeof(cmsFloat32Number)) return NULL;
    const cmsFloat32Number *values = (const cmsFloat32Number*)(Data + sizeof(cmsUInt32Number));
    return cmsBuildTabulatedToneCurveFloat(ContextID, nEntries, values);
}

static cmsToneCurve* create_random_segmented_tone_curve(cmsContext ContextID, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return NULL;
    cmsUInt32Number nSegments = *(cmsUInt32Number*)Data;
    if (nSegments == 0 || Size < sizeof(cmsUInt32Number) + nSegments * sizeof(cmsCurveSegment)) return NULL;
    const cmsCurveSegment *segments = (const cmsCurveSegment*)(Data + sizeof(cmsUInt32Number));
    return cmsBuildSegmentedToneCurve(ContextID, nSegments, segments);
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    cmsContext ContextID = NULL;

    // Create a tone curve using 16-bit values
    cmsToneCurve *curve16 = create_random_tone_curve16(ContextID, Data, Size);

    // Create a tone curve using float values
    cmsToneCurve *curveFloat = create_random_tone_curve_float(ContextID, Data, Size);

    // Attempt to join two tone curves
    if (curve16 != NULL && curveFloat != NULL) {
        cmsToneCurve *joinedCurve = cmsJoinToneCurve(ContextID, curve16, curveFloat, 128); // Arbitrary number of points
        if (joinedCurve != NULL) {
            cmsFreeToneCurve(joinedCurve);
        }
    }

    if (curve16 != NULL) {
        cmsUInt32Number nResultSamples = 256; // Arbitrary choice
        cmsToneCurve *reversedCurve = cmsReverseToneCurveEx(nResultSamples, curve16);
        if (reversedCurve) {
            cmsFreeToneCurve(reversedCurve);
        }
        cmsFreeToneCurve(curve16);
    }

    if (curveFloat != NULL) {
        cmsUInt32Number entries = cmsGetToneCurveEstimatedTableEntries(curveFloat);
        (void)entries; // Use the entries count in some way if needed
        cmsFreeToneCurve(curveFloat);
    }

    // Create segmented tone curve
    cmsToneCurve *segmentedCurve = create_random_segmented_tone_curve(ContextID, Data, Size);
    if (segmentedCurve != NULL) {
        cmsFreeToneCurve(segmentedCurve);
    }

    return 0;
}