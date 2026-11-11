// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsIT8SetPropertyDbl at cmscgats.c:1543:19 in lcms2.h
// cmsIT8GetProperty at cmscgats.c:1578:23 in lcms2.h
// cmsIT8GetDataDbl at cmscgats.c:2883:28 in lcms2.h
// cmsIT8GetPropertyDbl at cmscgats.c:1591:28 in lcms2.h
// cmsIT8GetPropertyMulti at cmscgats.c:1600:23 in lcms2.h
// cmsIT8SetDataDbl at cmscgats.c:2940:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

static cmsHANDLE createDummyIT8Handle() {
    // This function would create a dummy IT8 handle for testing.
    // In a real scenario, this should be properly initialized.
    // For simplicity, we will return NULL to avoid using uninitialized handles
    return NULL;
}

static void cleanupIT8Handle(cmsHANDLE hIT8) {
    // Clean up the dummy IT8 handle
    free(hIT8);
}

int LLVMFuzzerTestOneInput_116(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cmsHANDLE hIT8 = createDummyIT8Handle();
    if (!hIT8) return 0;

    // Use a portion of data for property name, patch, sample, etc.
    const size_t maxStrLen = 255;
    char propName[maxStrLen + 1];
    char patchName[maxStrLen + 1];
    char sampleName[maxStrLen + 1];
    
    size_t propNameLen = (Size > maxStrLen) ? maxStrLen : Size;
    memcpy(propName, Data, propNameLen);
    propName[propNameLen] = '\0';

    size_t patchNameLen = (Size > maxStrLen) ? maxStrLen : Size;
    memcpy(patchName, Data, patchNameLen);
    patchName[patchNameLen] = '\0';

    size_t sampleNameLen = (Size > maxStrLen) ? maxStrLen : Size;
    memcpy(sampleName, Data, sampleNameLen);
    sampleName[sampleNameLen] = '\0';

    // Use part of the data as a double value
    cmsFloat64Number doubleValue = 0.0;
    if (Size >= sizeof(cmsFloat64Number)) {
        memcpy(&doubleValue, Data, sizeof(cmsFloat64Number));
    }

    // Test cmsIT8SetPropertyDbl
    if (hIT8) {
        cmsBool setPropResult = cmsIT8SetPropertyDbl(hIT8, propName, doubleValue);
    }

    // Test cmsIT8GetProperty
    if (hIT8) {
        const char* getPropResult = cmsIT8GetProperty(hIT8, propName);
    }

    // Test cmsIT8GetDataDbl
    if (hIT8) {
        cmsFloat64Number getDataResult = cmsIT8GetDataDbl(hIT8, patchName, sampleName);
    }

    // Test cmsIT8GetPropertyDbl
    if (hIT8) {
        cmsFloat64Number getPropDblResult = cmsIT8GetPropertyDbl(hIT8, propName);
    }

    // Test cmsIT8GetPropertyMulti
    if (hIT8) {
        const char* getPropMultiResult = cmsIT8GetPropertyMulti(hIT8, propName, sampleName);
    }

    // Test cmsIT8SetDataDbl
    if (hIT8) {
        cmsBool setDataResult = cmsIT8SetDataDbl(hIT8, patchName, sampleName, doubleValue);
    }

    // Clean up
    cleanupIT8Handle(hIT8);

    return 0;
}