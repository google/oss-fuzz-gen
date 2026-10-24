// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8Alloc at cmscgats.c:1454:22 in lcms2.h
// cmsIT8Free at cmscgats.c:1170:16 in lcms2.h
// cmsIT8SetPropertyDbl at cmscgats.c:1543:19 in lcms2.h
// cmsIT8GetDataRowColDbl at cmscgats.c:2826:28 in lcms2.h
// cmsIT8SetDataRowCol at cmscgats.c:2838:19 in lcms2.h
// cmsIT8SetDataRowColDbl at cmscgats.c:2848:19 in lcms2.h
// cmsIT8GetPatchByName at cmscgats.c:2974:15 in lcms2.h
// cmsIT8SetDataDbl at cmscgats.c:2940:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsHANDLE create_dummy_it8_handle() {
    // For the purpose of fuzzing, we simulate a handle by allocating memory.
    // In a real scenario, this would be created by a specific lcms function.
    // We assume the IT8 handle requires more structured initialization.
    return cmsIT8Alloc(NULL);
}

static void destroy_dummy_it8_handle(cmsHANDLE hIT8) {
    cmsIT8Free((cmsHANDLE)hIT8);
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cmsHANDLE hIT8 = create_dummy_it8_handle();
    if (!hIT8) return 0;

    // Fuzz cmsIT8SetPropertyDbl
    const char* cProp = "SampleProperty";
    cmsFloat64Number Val = 123.456;
    cmsIT8SetPropertyDbl(hIT8, cProp, Val);

    // Fuzz cmsIT8GetDataRowColDbl
    int row = Data[0] % 256;
    int col = (Size > 1) ? Data[1] % 256 : 0;
    cmsIT8GetDataRowColDbl(hIT8, row, col);

    // Fuzz cmsIT8SetDataRowCol
    const char* ValStr = "SampleValue";
    cmsIT8SetDataRowCol(hIT8, row, col, ValStr);

    // Fuzz cmsIT8SetDataRowColDbl
    cmsIT8SetDataRowColDbl(hIT8, row, col, Val);

    // Fuzz cmsIT8GetPatchByName
    const char* cPatch = "SamplePatch";
    cmsIT8GetPatchByName(hIT8, cPatch);

    // Fuzz cmsIT8SetDataDbl
    const char* cSample = "SampleName";
    cmsIT8SetDataDbl(hIT8, cPatch, cSample, Val);

    destroy_dummy_it8_handle(hIT8);
    return 0;
}