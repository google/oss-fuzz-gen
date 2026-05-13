// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsMAT3inverse at cmsmtrx.c:129:20 in lcms2_plugin.h
// _cmsMAT3eval at cmsmtrx.c:169:16 in lcms2_plugin.h
// _cmsMAT3solve at cmsmtrx.c:156:20 in lcms2_plugin.h
// _cmsMAT3identity at cmsmtrx.c:84:16 in lcms2_plugin.h
// _cmsMAT3isIdentity at cmsmtrx.c:98:19 in lcms2_plugin.h
// _cmsMAT3per at cmsmtrx.c:114:16 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lcms2_plugin.h"

static void fuzz_cmsMAT3inverse(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsMAT3)) return;
    
    cmsMAT3 a, b;
    memcpy(&a, Data, sizeof(cmsMAT3));

    _cmsMAT3inverse(&a, &b);
}

static void fuzz_cmsMAT3eval(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsMAT3) + sizeof(cmsVEC3)) return;
    
    cmsMAT3 a;
    cmsVEC3 v, r;
    memcpy(&a, Data, sizeof(cmsMAT3));
    memcpy(&v, Data + sizeof(cmsMAT3), sizeof(cmsVEC3));

    _cmsMAT3eval(&r, &a, &v);
}

static void fuzz_cmsMAT3solve(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsMAT3) + sizeof(cmsVEC3)) return;
    
    cmsMAT3 a;
    cmsVEC3 b, x;
    memcpy(&a, Data, sizeof(cmsMAT3));
    memcpy(&b, Data + sizeof(cmsMAT3), sizeof(cmsVEC3));

    _cmsMAT3solve(&x, &a, &b);
}

static void fuzz_cmsMAT3identity(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsMAT3)) return;

    cmsMAT3 a;
    memcpy(&a, Data, sizeof(cmsMAT3));

    _cmsMAT3identity(&a);
}

static void fuzz_cmsMAT3isIdentity(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsMAT3)) return;

    cmsMAT3 a;
    memcpy(&a, Data, sizeof(cmsMAT3));

    _cmsMAT3isIdentity(&a);
}

static void fuzz_cmsMAT3per(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(cmsMAT3)) return;

    cmsMAT3 a, b, r;
    memcpy(&a, Data, sizeof(cmsMAT3));
    memcpy(&b, Data + sizeof(cmsMAT3), sizeof(cmsMAT3));

    _cmsMAT3per(&r, &a, &b);
}

int LLVMFuzzerTestOneInput_126(const uint8_t *Data, size_t Size) {
    fuzz_cmsMAT3inverse(Data, Size);
    fuzz_cmsMAT3eval(Data, Size);
    fuzz_cmsMAT3solve(Data, Size);
    fuzz_cmsMAT3identity(Data, Size);
    fuzz_cmsMAT3isIdentity(Data, Size);
    fuzz_cmsMAT3per(Data, Size);

    return 0;
}