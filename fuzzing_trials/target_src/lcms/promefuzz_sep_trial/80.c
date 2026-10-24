// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsXYZ2xyY at cmspcs.c:91:16 in lcms2.h
// cmsXYZ2Lab at cmspcs.c:143:16 in lcms2.h
// cmsD50_xyY at cmswtpnt.c:38:28 in lcms2.h
// cmsxyY2XYZ at cmspcs.c:102:16 in lcms2.h
// cmsTempFromWhitePoint at cmswtpnt.c:143:20 in lcms2.h
// cmsCreateLab4Profile at cmsvirt.c:570:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static cmsCIEXYZ generateRandomXYZ(const uint8_t *Data, size_t Size, size_t *Offset) {
    cmsCIEXYZ xyz;
    if (*Offset + sizeof(cmsCIEXYZ) <= Size) {
        memcpy(&xyz, Data + *Offset, sizeof(cmsCIEXYZ));
        *Offset += sizeof(cmsCIEXYZ);
    } else {
        xyz.X = 0.0;
        xyz.Y = 0.0;
        xyz.Z = 0.0;
    }
    return xyz;
}

static cmsCIExyY generateRandomxyY(const uint8_t *Data, size_t Size, size_t *Offset) {
    cmsCIExyY xyY;
    if (*Offset + sizeof(cmsCIExyY) <= Size) {
        memcpy(&xyY, Data + *Offset, sizeof(cmsCIExyY));
        *Offset += sizeof(cmsCIExyY);
    } else {
        xyY.x = 0.0;
        xyY.y = 0.0;
        xyY.Y = 0.0;
    }
    return xyY;
}

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    size_t offset = 0;

    // Test cmsXYZ2xyY
    cmsCIExyY xyY;
    cmsCIEXYZ xyz = generateRandomXYZ(Data, Size, &offset);
    cmsXYZ2xyY(&xyY, &xyz);

    // Test cmsXYZ2Lab
    cmsCIELab Lab;
    cmsCIEXYZ WhitePoint = generateRandomXYZ(Data, Size, &offset);
    cmsXYZ2Lab(&WhitePoint, &Lab, &xyz);

    // Test cmsD50_xyY
    const cmsCIExyY* D50xyY = cmsD50_xyY();

    // Test cmsxyY2XYZ
    cmsCIEXYZ DestXYZ;
    cmsxyY2XYZ(&DestXYZ, D50xyY);

    // Test cmsTempFromWhitePoint
    cmsFloat64Number TempK;
    cmsTempFromWhitePoint(&TempK, D50xyY);

    // Test cmsCreateLab4Profile
    cmsHPROFILE profile = cmsCreateLab4Profile(D50xyY);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}