// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCMCdeltaE at cmspcs.c:548:28 in lcms2.h
// cmsDeltaE at cmspcs.c:438:28 in lcms2.h
// cmsCIE94DeltaE at cmspcs.c:451:28 in lcms2.h
// cmsDesaturateLab at cmsgmt.c:515:19 in lcms2.h
// cmsCIE2000DeltaE at cmspcs.c:589:28 in lcms2.h
// cmsBFDdeltaE at cmspcs.c:497:28 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsCIELab GenerateRandomCIELab(const uint8_t **Data, size_t *Size) {
    cmsCIELab Lab;
    if (*Size < 3 * sizeof(cmsFloat64Number)) {
        exit(0);
    }
    memcpy(&Lab.L, *Data, sizeof(cmsFloat64Number));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);

    memcpy(&Lab.a, *Data, sizeof(cmsFloat64Number));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);

    memcpy(&Lab.b, *Data, sizeof(cmsFloat64Number));
    *Data += sizeof(cmsFloat64Number);
    *Size -= sizeof(cmsFloat64Number);

    return Lab;
}

int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size) {
    if (Size < 6 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsCIELab Lab1 = GenerateRandomCIELab(&Data, &Size);
    cmsCIELab Lab2 = GenerateRandomCIELab(&Data, &Size);

    if (Size < 5 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsFloat64Number l, c, Kl, Kc, Kh;
    memcpy(&l, Data, sizeof(cmsFloat64Number));
    Data += sizeof(cmsFloat64Number);
    Size -= sizeof(cmsFloat64Number);

    memcpy(&c, Data, sizeof(cmsFloat64Number));
    Data += sizeof(cmsFloat64Number);
    Size -= sizeof(cmsFloat64Number);

    memcpy(&Kl, Data, sizeof(cmsFloat64Number));
    Data += sizeof(cmsFloat64Number);
    Size -= sizeof(cmsFloat64Number);

    memcpy(&Kc, Data, sizeof(cmsFloat64Number));
    Data += sizeof(cmsFloat64Number);
    Size -= sizeof(cmsFloat64Number);

    memcpy(&Kh, Data, sizeof(cmsFloat64Number));
    Data += sizeof(cmsFloat64Number);
    Size -= sizeof(cmsFloat64Number);

    // Test cmsCMCdeltaE
    cmsFloat64Number deltaE_CMC = cmsCMCdeltaE(&Lab1, &Lab2, l, c);

    // Test cmsDeltaE
    cmsFloat64Number deltaE = cmsDeltaE(&Lab1, &Lab2);

    // Test cmsCIE94DeltaE
    cmsFloat64Number deltaE_CIE94 = cmsCIE94DeltaE(&Lab1, &Lab2);

    // Test cmsDesaturateLab
    cmsBool desaturateResult = cmsDesaturateLab(&Lab1, l, -l, c, -c);

    // Test cmsCIE2000DeltaE
    cmsFloat64Number deltaE_CIE2000 = cmsCIE2000DeltaE(&Lab1, &Lab2, Kl, Kc, Kh);

    // Test cmsBFDdeltaE
    cmsFloat64Number deltaE_BFD = cmsBFDdeltaE(&Lab1, &Lab2);

    // Use the results to prevent optimizations
    volatile cmsFloat64Number results[] = {deltaE_CMC, deltaE, deltaE_CIE94, deltaE_CIE2000, deltaE_BFD};
    volatile cmsBool desaturate = desaturateResult;

    return 0;
}