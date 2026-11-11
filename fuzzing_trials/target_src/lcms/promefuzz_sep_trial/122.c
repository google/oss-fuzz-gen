// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateDeviceLinkFromCubeFileTHR at cmscgats.c:3211:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateDeviceLinkFromCubeFile at cmscgats.c:3289:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsOpenProfileFromStream at cmsio0.c:1265:24 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsOpenProfileFromFileTHR at cmsio0.c:1204:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsOpenProfileFromIOhandler2THR at cmsio0.c:1178:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

typedef struct _cms_io_handler {
    void* stream;
    cmsContext ContextID;
    cmsUInt32Number UsedSpace;
    cmsUInt32Number ReportedSize;
    char PhysicalFile[256];

    cmsUInt32Number (* Read)(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count);
    cmsBool (* Seek)(struct _cms_io_handler* iohandler, cmsUInt32Number offset);
    cmsBool (* Close)(struct _cms_io_handler* iohandler);
    cmsUInt32Number (* Tell)(struct _cms_io_handler* iohandler);
    cmsBool (* Write)(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer);
} cmsIOHANDLER;

static cmsUInt32Number dummyRead(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    return fread(Buffer, size, count, (FILE *)iohandler->stream);
}

static cmsBool dummyClose(struct _cms_io_handler* iohandler) {
    if (iohandler->stream != NULL) {
        fclose((FILE *)iohandler->stream);
        iohandler->stream = NULL; // Avoid double-free
    }
    return 1;
}

static void fuzz_cmsCreateDeviceLinkFromCubeFile(const uint8_t *Data, size_t Size) {
    char fileName[] = "./dummy_file";
    FILE *file = fopen(fileName, "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFile(fileName);
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
    }
}

static void fuzz_cmsOpenProfileFromStream(const uint8_t *Data, size_t Size) {
    char mode[] = "r";
    FILE *file = fmemopen((void *)Data, Size, mode);
    if (file != NULL) {
        cmsHPROFILE profile = cmsOpenProfileFromStream(file, mode);
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
        // No need to fclose(file) here as fmemopen does not require it.
    }
}

static void fuzz_cmsOpenProfileFromFileTHR(const uint8_t *Data, size_t Size) {
    char fileName[] = "./dummy_file";
    char mode[] = "r";
    FILE *file = fopen(fileName, "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        cmsContext context = NULL;
        cmsHPROFILE profile = cmsOpenProfileFromFileTHR(context, fileName, mode);
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
    }
}

static void fuzz_cmsOpenProfileFromIOhandler2THR(const uint8_t *Data, size_t Size) {
    cmsContext context = NULL;
    cmsIOHANDLER ioHandler;
    memset(&ioHandler, 0, sizeof(ioHandler));
    ioHandler.ContextID = context;
    ioHandler.stream = fmemopen((void *)Data, Size, "r");
    ioHandler.Read = dummyRead;
    ioHandler.Close = dummyClose;
    cmsBool write = 0;
    if (ioHandler.stream != NULL) {
        cmsHPROFILE profile = cmsOpenProfileFromIOhandler2THR(context, &ioHandler, write);
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
        ioHandler.Close(&ioHandler);
    }
}

static void fuzz_cmsOpenProfileFromFile(const uint8_t *Data, size_t Size) {
    char fileName[] = "./dummy_file";
    char mode[] = "r";
    FILE *file = fopen(fileName, "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        cmsHPROFILE profile = cmsOpenProfileFromFile(fileName, mode);
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
    }
}

static void fuzz_cmsCreateDeviceLinkFromCubeFileTHR(const uint8_t *Data, size_t Size) {
    char fileName[] = "./dummy_file";
    FILE *file = fopen(fileName, "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        cmsContext context = NULL;
        cmsHPROFILE profile = cmsCreateDeviceLinkFromCubeFileTHR(context, fileName);
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
    }
}

int LLVMFuzzerTestOneInput_122(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateDeviceLinkFromCubeFile(Data, Size);
    fuzz_cmsOpenProfileFromStream(Data, Size);
    fuzz_cmsOpenProfileFromFileTHR(Data, Size);
    fuzz_cmsOpenProfileFromIOhandler2THR(Data, Size);
    fuzz_cmsOpenProfileFromFile(Data, Size);
    fuzz_cmsCreateDeviceLinkFromCubeFileTHR(Data, Size);
    return 0;
}