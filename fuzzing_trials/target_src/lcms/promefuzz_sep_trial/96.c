// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3distance at cmsmtrx.c:72:28 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3cross at cmsmtrx.c:50:16 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3dot at cmsmtrx.c:58:28 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3minus at cmsmtrx.c:42:16 in lcms2_plugin.h
// _cmsVEC3init at cmsmtrx.c:34:16 in lcms2_plugin.h
// _cmsVEC3length at cmsmtrx.c:64:28 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2_plugin.h"

static void fuzz_cmsVEC3distance(const uint8_t *Data, size_t Size) {
    if (Size < 6 * sizeof(cmsFloat64Number)) return;

    cmsVEC3 a, b;
    _cmsVEC3init(&a, ((cmsFloat64Number*)Data)[0], ((cmsFloat64Number*)Data)[1], ((cmsFloat64Number*)Data)[2]);
    _cmsVEC3init(&b, ((cmsFloat64Number*)Data)[3], ((cmsFloat64Number*)Data)[4], ((cmsFloat64Number*)Data)[5]);

    cmsFloat64Number distance = _cmsVEC3distance(&a, &b);
    (void)distance;
}

static void fuzz_cmsVEC3cross(const uint8_t *Data, size_t Size) {
    if (Size < 9 * sizeof(cmsFloat64Number)) return;

    cmsVEC3 r, u, v;
    _cmsVEC3init(&u, ((cmsFloat64Number*)Data)[0], ((cmsFloat64Number*)Data)[1], ((cmsFloat64Number*)Data)[2]);
    _cmsVEC3init(&v, ((cmsFloat64Number*)Data)[3], ((cmsFloat64Number*)Data)[4], ((cmsFloat64Number*)Data)[5]);

    _cmsVEC3cross(&r, &u, &v);
}

static void fuzz_cmsVEC3dot(const uint8_t *Data, size_t Size) {
    if (Size < 6 * sizeof(cmsFloat64Number)) return;

    cmsVEC3 u, v;
    _cmsVEC3init(&u, ((cmsFloat64Number*)Data)[0], ((cmsFloat64Number*)Data)[1], ((cmsFloat64Number*)Data)[2]);
    _cmsVEC3init(&v, ((cmsFloat64Number*)Data)[3], ((cmsFloat64Number*)Data)[4], ((cmsFloat64Number*)Data)[5]);

    cmsFloat64Number dotProduct = _cmsVEC3dot(&u, &v);
    (void)dotProduct;
}

static void fuzz_cmsVEC3minus(const uint8_t *Data, size_t Size) {
    if (Size < 9 * sizeof(cmsFloat64Number)) return;

    cmsVEC3 r, a, b;
    _cmsVEC3init(&a, ((cmsFloat64Number*)Data)[0], ((cmsFloat64Number*)Data)[1], ((cmsFloat64Number*)Data)[2]);
    _cmsVEC3init(&b, ((cmsFloat64Number*)Data)[3], ((cmsFloat64Number*)Data)[4], ((cmsFloat64Number*)Data)[5]);

    _cmsVEC3minus(&r, &a, &b);
}

static void fuzz_cmsVEC3length(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(cmsFloat64Number)) return;

    cmsVEC3 a;
    _cmsVEC3init(&a, ((cmsFloat64Number*)Data)[0], ((cmsFloat64Number*)Data)[1], ((cmsFloat64Number*)Data)[2]);

    cmsFloat64Number length = _cmsVEC3length(&a);
    (void)length;
}

int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size) {
    fuzz_cmsVEC3distance(Data, Size);
    fuzz_cmsVEC3cross(Data, Size);
    fuzz_cmsVEC3dot(Data, Size);
    fuzz_cmsVEC3minus(Data, Size);
    fuzz_cmsVEC3length(Data, Size);
    return 0;
}