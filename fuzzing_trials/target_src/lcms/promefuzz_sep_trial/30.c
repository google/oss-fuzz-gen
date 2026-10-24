// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsGetHeaderFlags at cmsio0.c:997:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetHeaderModel at cmsio0.c:1027:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsIsCLUT at cmsio1.c:830:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetPostScriptColorResource at cmsps2.c:1525:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSaveProfileToIOhandler at cmsio0.c:1447:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

// Define a dummy cmsIOHANDLER to avoid incomplete type errors
typedef struct {
    void* stream;
    cmsContext ContextID;
    cmsUInt32Number UsedSpace;
    cmsUInt32Number ReportedSize;
    char PhysicalFile[256];
    cmsUInt32Number (*Read)(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count);
    cmsBool (*Seek)(struct _cms_io_handler* iohandler, cmsUInt32Number offset);
    cmsBool (*Close)(struct _cms_io_handler* iohandler);
    cmsUInt32Number (*Tell)(struct _cms_io_handler* iohandler);
    cmsBool (*Write)(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer);
} DummyIOHANDLER;

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    return hProfile;
}

static void fuzz_cmsCreateMultiprofileTransform(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsHPROFILE) + 4 * sizeof(cmsUInt32Number)) return;

    cmsHPROFILE hProfiles[255];
    cmsUInt32Number nProfiles = Data[0] % 256; // Limit to 255 profiles
    Data++; Size--;

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        hProfiles[i] = createDummyProfile();
    }

    if (Size < 4 * sizeof(cmsUInt32Number)) return;

    cmsUInt32Number InputFormat = *(cmsUInt32Number*)Data; Data += sizeof(cmsUInt32Number);
    cmsUInt32Number OutputFormat = *(cmsUInt32Number*)Data; Data += sizeof(cmsUInt32Number);
    cmsUInt32Number Intent = *(cmsUInt32Number*)Data; Data += sizeof(cmsUInt32Number);
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)Data;

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(hProfiles, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);
    if (transform) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(hProfiles[i]);
    }
}

static void fuzz_cmsIsCLUT(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsHPROFILE) + 2 * sizeof(cmsUInt32Number)) return;

    cmsHPROFILE hProfile = createDummyProfile();
    cmsUInt32Number Intent = *(cmsUInt32Number*)Data; Data += sizeof(cmsUInt32Number);
    cmsUInt32Number UsedDirection = *(cmsUInt32Number*)Data;

    cmsIsCLUT(hProfile, Intent, UsedDirection);

    cmsCloseProfile(hProfile);
}

static void fuzz_cmsGetPostScriptColorResource(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsContext) + sizeof(cmsPSResourceType) + sizeof(cmsHPROFILE) + 2 * sizeof(cmsUInt32Number)) return;

    cmsContext ContextID = (cmsContext) Data;
    Data += sizeof(cmsContext);
    Size -= sizeof(cmsContext);

    cmsPSResourceType Type = *(cmsPSResourceType*)Data; Data += sizeof(cmsPSResourceType);
    cmsHPROFILE hProfile = createDummyProfile();

    cmsUInt32Number Intent = *(cmsUInt32Number*)Data; Data += sizeof(cmsUInt32Number);
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)Data;

    DummyIOHANDLER ioHandler = {0};
    cmsGetPostScriptColorResource(ContextID, Type, hProfile, Intent, dwFlags, (cmsIOHANDLER*)&ioHandler);

    cmsCloseProfile(hProfile);
}

static void fuzz_cmsSaveProfileToIOhandler(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsHPROFILE) + sizeof(DummyIOHANDLER)) return;

    cmsHPROFILE hProfile = createDummyProfile();
    DummyIOHANDLER ioHandler = {0};
    cmsSaveProfileToIOhandler(hProfile, (cmsIOHANDLER*)&ioHandler);

    cmsCloseProfile(hProfile);
}

static void fuzz_cmsGetHeaderFlags(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsHPROFILE)) return;

    cmsHPROFILE hProfile = createDummyProfile();
    cmsGetHeaderFlags(hProfile);
    cmsCloseProfile(hProfile);
}

static void fuzz_cmsGetHeaderModel(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsHPROFILE)) return;

    cmsHPROFILE hProfile = createDummyProfile();
    cmsGetHeaderModel(hProfile);
    cmsCloseProfile(hProfile);
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateMultiprofileTransform(Data, Size);
    fuzz_cmsIsCLUT(Data, Size);
    fuzz_cmsGetPostScriptColorResource(Data, Size);
    fuzz_cmsSaveProfileToIOhandler(Data, Size);
    fuzz_cmsGetHeaderFlags(Data, Size);
    fuzz_cmsGetHeaderModel(Data, Size);
    return 0;
}