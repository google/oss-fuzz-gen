// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsWriteUInt16Number at cmsplugin.c:268:20 in lcms2_plugin.h
// _cmsAdjustEndianess64 at cmsplugin.c:79:17 in lcms2_plugin.h
// _cmsWriteUInt64Number at cmsplugin.c:324:20 in lcms2_plugin.h
// _cmsReadUInt64Number at cmsplugin.c:206:21 in lcms2_plugin.h
// cmsOpenProfileFromMem at cmsio0.c:1296:23 in lcms2.h
// cmsGetHeaderAttributes at cmsio0.c:1039:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// _cmsReadUInt16Number at cmsplugin.c:124:20 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

#define DUMMY_FILE "./dummy_file"

static cmsUInt32Number dummy_read(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    return fread(Buffer, size, count, (FILE*)iohandler->stream);
}

static cmsBool dummy_seek(struct _cms_io_handler* iohandler, cmsUInt32Number offset) {
    return fseek((FILE*)iohandler->stream, offset, SEEK_SET) == 0;
}

static cmsBool dummy_close(struct _cms_io_handler* iohandler) {
    return fclose((FILE*)iohandler->stream) == 0;
}

static cmsUInt32Number dummy_tell(struct _cms_io_handler* iohandler) {
    return ftell((FILE*)iohandler->stream);
}

static cmsBool dummy_write(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer) {
    return fwrite(Buffer, 1, size, (FILE*)iohandler->stream) == size;
}

static cmsIOHANDLER* create_dummy_iohandler(void) {
    cmsIOHANDLER* iohandler = (cmsIOHANDLER*)malloc(sizeof(cmsIOHANDLER));
    if (!iohandler) return NULL;

    iohandler->stream = fopen(DUMMY_FILE, "w+b");
    if (!iohandler->stream) {
        free(iohandler);
        return NULL;
    }

    iohandler->Read = dummy_read;
    iohandler->Seek = dummy_seek;
    iohandler->Close = dummy_close;
    iohandler->Tell = dummy_tell;
    iohandler->Write = dummy_write;

    return iohandler;
}

static void destroy_dummy_iohandler(cmsIOHANDLER* iohandler) {
    if (iohandler) {
        iohandler->Close(iohandler);
        free(iohandler);
    }
}

int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt64Number) + sizeof(cmsUInt16Number)) return 0;

    cmsIOHANDLER* iohandler = create_dummy_iohandler();
    if (!iohandler) return 0;

    cmsUInt16Number u16;
    cmsUInt64Number u64, result;

    memcpy(&u16, Data, sizeof(cmsUInt16Number));
    memcpy(&u64, Data + sizeof(cmsUInt16Number), sizeof(cmsUInt64Number));

    // Fuzz _cmsWriteUInt16Number
    _cmsWriteUInt16Number(iohandler, u16);

    // Fuzz _cmsAdjustEndianess64
    _cmsAdjustEndianess64(&result, &u64);

    // Fuzz _cmsWriteUInt64Number
    _cmsWriteUInt64Number(iohandler, &u64);

    // Fuzz _cmsReadUInt64Number
    iohandler->Seek(iohandler, 0);
    _cmsReadUInt64Number(iohandler, &result);

    // Fuzz cmsGetHeaderAttributes
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(Data, Size);
    if (hProfile) {
        cmsGetHeaderAttributes(hProfile, &result);
        cmsCloseProfile(hProfile);
    }

    // Fuzz _cmsReadUInt16Number
    iohandler->Seek(iohandler, 0);
    _cmsReadUInt16Number(iohandler, &u16);

    destroy_dummy_iohandler(iohandler);
    return 0;
}