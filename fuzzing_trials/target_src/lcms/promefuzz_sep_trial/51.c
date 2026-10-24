// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsFloat2XYZEncoded at cmspcs.c:374:16 in lcms2.h
// cmsXYZEncoded2Float at cmspcs.c:429:16 in lcms2.h
// _cmsDoubleTo8Fixed8 at cmsplugin.c:370:27 in lcms2_plugin.h
// _cmsAdjustEndianess16 at cmsplugin.c:37:28 in lcms2_plugin.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsEvalToneCurve16 at cmsgamma.c:1437:27 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// _cms8Fixed8toDouble at cmsplugin.c:365:28 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <lcms2_plugin.h>

static void fuzz_cmsFloat2XYZEncoded(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIEXYZ)) return;

    cmsCIEXYZ fXYZ;
    cmsUInt16Number XYZ[3];

    memcpy(&fXYZ, Data, sizeof(cmsCIEXYZ));
    cmsFloat2XYZEncoded(XYZ, &fXYZ);
}

static void fuzz_cmsXYZEncoded2Float(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(cmsUInt16Number)) return;

    cmsCIEXYZ fXYZ;
    cmsUInt16Number XYZ[3];

    memcpy(XYZ, Data, 3 * sizeof(cmsUInt16Number));
    cmsXYZEncoded2Float(&fXYZ, XYZ);
}

static void fuzz__cmsDoubleTo8Fixed8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return;

    cmsFloat64Number val;
    memcpy(&val, Data, sizeof(cmsFloat64Number));

    _cmsDoubleTo8Fixed8(val);
}

static void fuzz__cmsAdjustEndianess16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number)) return;

    cmsUInt16Number Word;
    memcpy(&Word, Data, sizeof(cmsUInt16Number));

    _cmsAdjustEndianess16(Word);
}

static void fuzz_cmsEvalToneCurve16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number)) return;

    cmsToneCurve* Curve = cmsBuildGamma(NULL, 2.2); // Create a simple gamma curve for testing
    cmsUInt16Number v;
    memcpy(&v, Data, sizeof(cmsUInt16Number));

    if (Curve != NULL) {
        cmsEvalToneCurve16(Curve, v);
        cmsFreeToneCurve(Curve); // Clean up the curve
    }
}

static void fuzz__cms8Fixed8toDouble(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt16Number)) return;

    cmsUInt16Number fixed8;
    memcpy(&fixed8, Data, sizeof(cmsUInt16Number));

    _cms8Fixed8toDouble(fixed8);
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    fuzz_cmsFloat2XYZEncoded(Data, Size);
    fuzz_cmsXYZEncoded2Float(Data, Size);
    fuzz__cmsDoubleTo8Fixed8(Data, Size);
    fuzz__cmsAdjustEndianess16(Data, Size);
    fuzz_cmsEvalToneCurve16(Data, Size);
    fuzz__cms8Fixed8toDouble(Data, Size);

    return 0;
}