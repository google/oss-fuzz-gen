// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsReadXYZNumber at cmsplugin.c:241:20 in lcms2_plugin.h
// cmsAdaptToIlluminant at cmswtpnt.c:328:19 in lcms2.h
// cmsFloat2XYZEncoded at cmspcs.c:374:16 in lcms2.h
// cmsLab2XYZ at cmspcs.c:161:16 in lcms2.h
// cmsXYZEncoded2Float at cmspcs.c:429:16 in lcms2.h
// cmsxyY2XYZ at cmspcs.c:102:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

static cmsCIEXYZ RandomCIEXYZ(const uint8_t **Data, size_t *Size) {
    cmsCIEXYZ xyz;
    if (*Size < 3 * sizeof(double)) {
        memset(&xyz, 0, sizeof(cmsCIEXYZ));
        return xyz;
    }
    memcpy(&xyz, *Data, sizeof(cmsCIEXYZ));
    *Data += sizeof(cmsCIEXYZ);
    *Size -= sizeof(cmsCIEXYZ);
    return xyz;
}

static cmsCIELab RandomCIELab(const uint8_t **Data, size_t *Size) {
    cmsCIELab lab;
    if (*Size < 3 * sizeof(double)) {
        memset(&lab, 0, sizeof(cmsCIELab));
        return lab;
    }
    memcpy(&lab, *Data, sizeof(cmsCIELab));
    *Data += sizeof(cmsCIELab);
    *Size -= sizeof(cmsCIELab);
    return lab;
}

static cmsCIExyY RandomCIExyY(const uint8_t **Data, size_t *Size) {
    cmsCIExyY xyY;
    if (*Size < 3 * sizeof(double)) {
        memset(&xyY, 0, sizeof(cmsCIExyY));
        return xyY;
    }
    memcpy(&xyY, *Data, sizeof(cmsCIExyY));
    *Data += sizeof(cmsCIExyY);
    *Size -= sizeof(cmsCIExyY);
    return xyY;
}

static cmsUInt16Number RandomUInt16Number(const uint8_t **Data, size_t *Size) {
    if (*Size < sizeof(cmsUInt16Number)) {
        return 0;
    }
    cmsUInt16Number num;
    memcpy(&num, *Data, sizeof(cmsUInt16Number));
    *Data += sizeof(cmsUInt16Number);
    *Size -= sizeof(cmsUInt16Number);
    return num;
}

static void FuzzcmsAdaptToIlluminant(const uint8_t **Data, size_t *Size) {
    cmsCIEXYZ Result, SourceWhitePt, Illuminant, Value;
    SourceWhitePt = RandomCIEXYZ(Data, Size);
    Illuminant = RandomCIEXYZ(Data, Size);
    Value = RandomCIEXYZ(Data, Size);
    cmsAdaptToIlluminant(&Result, &SourceWhitePt, &Illuminant, &Value);
}

static void FuzzcmsFloat2XYZEncoded(const uint8_t **Data, size_t *Size) {
    cmsCIEXYZ fXYZ = RandomCIEXYZ(Data, Size);
    cmsUInt16Number XYZ[3];
    cmsFloat2XYZEncoded(XYZ, &fXYZ);
}

static void FuzzcmsLab2XYZ(const uint8_t **Data, size_t *Size) {
    cmsCIEXYZ xyz, WhitePoint = RandomCIEXYZ(Data, Size);
    cmsCIELab Lab = RandomCIELab(Data, Size);
    cmsLab2XYZ(&WhitePoint, &xyz, &Lab);
}

static void FuzzcmsXYZEncoded2Float(const uint8_t **Data, size_t *Size) {
    cmsCIEXYZ fxyz;
    cmsUInt16Number XYZ[3];
    for (int i = 0; i < 3; i++) {
        XYZ[i] = RandomUInt16Number(Data, Size);
    }
    cmsXYZEncoded2Float(&fxyz, XYZ);
}

static void FuzzcmsxyY2XYZ(const uint8_t **Data, size_t *Size) {
    cmsCIEXYZ Dest;
    cmsCIExyY Source = RandomCIExyY(Data, Size);
    cmsxyY2XYZ(&Dest, &Source);
}

static cmsUInt32Number DummyRead(cmsIOHANDLER *iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    memcpy(Buffer, iohandler->stream, size * count);
    iohandler->stream = (uint8_t*)iohandler->stream + size * count;
    return size * count;
}

static void Fuzz_cmsReadXYZNumber(const uint8_t **Data, size_t *Size) {
    if (*Size < sizeof(cmsEncodedXYZNumber)) return;

    cmsIOHANDLER io;
    cmsCIEXYZ XYZ;
    memset(&io, 0, sizeof(cmsIOHANDLER));

    io.stream = (void*)*Data;
    io.ReportedSize = *Size;
    io.Read = DummyRead;

    _cmsReadXYZNumber(&io, &XYZ);
}

int LLVMFuzzerTestOneInput_110(const uint8_t *Data, size_t Size) {
    FuzzcmsAdaptToIlluminant(&Data, &Size);
    FuzzcmsFloat2XYZEncoded(&Data, &Size);
    FuzzcmsLab2XYZ(&Data, &Size);
    FuzzcmsXYZEncoded2Float(&Data, &Size);
    FuzzcmsxyY2XYZ(&Data, &Size);
    Fuzz_cmsReadXYZNumber(&Data, &Size);
    return 0;
}