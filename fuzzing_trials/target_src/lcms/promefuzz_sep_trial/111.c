// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCMCdeltaE at cmspcs.c:548:28 in lcms2.h
// cmsCIE94DeltaE at cmspcs.c:451:28 in lcms2.h
// cmsGDBAddPoint at cmssm.c:358:19 in lcms2.h
// cmsGDBCompute at cmssm.c:550:19 in lcms2.h
// cmsGDBCheckPoint at cmssm.c:390:19 in lcms2.h
// cmsDesaturateLab at cmsgmt.c:515:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "lcms2.h"

static cmsCIELab GenerateRandomCIELab(const uint8_t **Data, size_t *Size) {
    cmsCIELab lab;
    if (*Size < sizeof(cmsFloat64Number) * 3) {
        exit(0);
    }
    lab.L = *((cmsFloat64Number*)(*Data));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);
    lab.a = *((cmsFloat64Number*)(*Data));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);
    lab.b = *((cmsFloat64Number*)(*Data));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);
    return lab;
}

static cmsFloat64Number GenerateRandomFloat64(const uint8_t **Data, size_t *Size) {
    if (*Size < sizeof(cmsFloat64Number)) {
        exit(0);
    }
    cmsFloat64Number value = *((cmsFloat64Number*)(*Data));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);
    return value;
}

static cmsHANDLE CreateDummyGDB() {
    // Dummy GBD handle creation
    return NULL; // Placeholder, as actual GBD creation is not defined
}

static void CleanupDummyGDB(cmsHANDLE hGDB) {
    // Placeholder for cleanup, as actual GBD cleanup is not defined
}

int LLVMFuzzerTestOneInput_111(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 6) {
        return 0; // Not enough data for all operations
    }

    const uint8_t *DataPtr = Data;

    cmsCIELab Lab1 = GenerateRandomCIELab(&DataPtr, &Size);
    cmsCIELab Lab2 = GenerateRandomCIELab(&DataPtr, &Size);

    cmsFloat64Number l = GenerateRandomFloat64(&DataPtr, &Size);
    cmsFloat64Number c = GenerateRandomFloat64(&DataPtr, &Size);

    cmsCMCdeltaE(&Lab1, &Lab2, l, c);
    cmsCIE94DeltaE(&Lab1, &Lab2);

    cmsHANDLE hGDB = CreateDummyGDB();
    if (hGDB != NULL) {
        cmsGDBAddPoint(hGDB, &Lab1);
        cmsGDBCompute(hGDB, (cmsUInt32Number)Size);
        cmsGDBCheckPoint(hGDB, &Lab2);
        CleanupDummyGDB(hGDB);
    }

    cmsFloat64Number amax = GenerateRandomFloat64(&DataPtr, &Size);
    cmsFloat64Number amin = GenerateRandomFloat64(&DataPtr, &Size);
    cmsFloat64Number bmax = GenerateRandomFloat64(&DataPtr, &Size);
    cmsFloat64Number bmin = GenerateRandomFloat64(&DataPtr, &Size);

    cmsDesaturateLab(&Lab1, amax, amin, bmax, bmin);

    return 0;
}