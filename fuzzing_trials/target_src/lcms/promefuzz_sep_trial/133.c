// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8SetPropertyDbl at cmscgats.c:1543:19 in lcms2.h
// cmsIT8DefineDblFormat at cmscgats.c:3041:16 in lcms2.h
// cmsIT8GetDataDbl at cmscgats.c:2883:28 in lcms2.h
// cmsIT8GetPropertyDbl at cmscgats.c:1591:28 in lcms2.h
// cmsIT8GetSheetType at cmscgats.c:1508:23 in lcms2.h
// cmsIT8SetDataDbl at cmscgats.c:2940:19 in lcms2.h
// cmsIT8Alloc at cmscgats.c:1454:22 in lcms2.h
// cmsIT8Free at cmscgats.c:1170:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static void fuzz_cmsIT8SetPropertyDbl(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) + 1) return;
    cmsFloat64Number val;
    memcpy(&val, Data, sizeof(cmsFloat64Number));
    const char* prop = (const char*)(Data + sizeof(cmsFloat64Number));
    size_t propLen = strnlen(prop, Size - sizeof(cmsFloat64Number));
    if (propLen >= Size - sizeof(cmsFloat64Number)) return;
    cmsIT8SetPropertyDbl(hIT8, prop, val);
}

static void fuzz_cmsIT8DefineDblFormat(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size == 0) return;
    size_t maxLen = Size < 256 ? Size : 255; 
    char formatter[256];
    snprintf(formatter, maxLen + 1, "%.*s", (int)maxLen, (const char*)Data);
    cmsIT8DefineDblFormat(hIT8, formatter);
}

static void fuzz_cmsIT8GetDataDbl(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    const char* patch = (const char*)Data;
    size_t patchLen = strnlen(patch, Size);
    if (patchLen >= Size - 1) return;
    const char* sample = (const char*)(Data + patchLen + 1);
    size_t sampleLen = strnlen(sample, Size - patchLen - 1);
    if (sampleLen >= Size - patchLen - 1) return;
    cmsIT8GetDataDbl(hIT8, patch, sample);
}

static void fuzz_cmsIT8GetPropertyDbl(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size == 0) return;
    const char* prop = (const char*)Data;
    size_t propLen = strnlen(prop, Size);
    if (propLen >= Size) return;
    cmsIT8GetPropertyDbl(hIT8, prop);
}

static void fuzz_cmsIT8GetSheetType(cmsHANDLE hIT8) {
    cmsIT8GetSheetType(hIT8);
}

static void fuzz_cmsIT8SetDataDbl(cmsHANDLE hIT8, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) + 2) return;
    cmsFloat64Number val;
    memcpy(&val, Data, sizeof(cmsFloat64Number));
    const char* patch = (const char*)(Data + sizeof(cmsFloat64Number));
    size_t patchLen = strnlen(patch, Size - sizeof(cmsFloat64Number));
    if (patchLen >= Size - sizeof(cmsFloat64Number) - 1) return;
    const char* sample = (const char*)(Data + sizeof(cmsFloat64Number) + patchLen + 1);
    size_t sampleLen = strnlen(sample, Size - sizeof(cmsFloat64Number) - patchLen - 1);
    if (sampleLen >= Size - sizeof(cmsFloat64Number) - patchLen - 1) return;
    cmsIT8SetDataDbl(hIT8, patch, sample, val);
}

int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size) {
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (!hIT8) return 0;

    fuzz_cmsIT8SetPropertyDbl(hIT8, Data, Size);
    fuzz_cmsIT8DefineDblFormat(hIT8, Data, Size);
    fuzz_cmsIT8GetDataDbl(hIT8, Data, Size);
    fuzz_cmsIT8GetPropertyDbl(hIT8, Data, Size);
    fuzz_cmsIT8GetSheetType(hIT8);
    fuzz_cmsIT8SetDataDbl(hIT8, Data, Size);

    cmsIT8Free(hIT8);
    return 0;
}