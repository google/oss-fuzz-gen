// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsReadFloat32Number at cmsplugin.c:169:20 in lcms2_plugin.h
// _cmsWriteAlignment at cmsplugin.c:462:19 in lcms2_plugin.h
// _cmsReadUInt8Number at cmsplugin.c:111:20 in lcms2_plugin.h
// _cmsWriteUInt32Number at cmsplugin.c:295:20 in lcms2_plugin.h
// _cmsWriteUInt8Number at cmsplugin.c:258:20 in lcms2_plugin.h
// _cmsReadAlignment at cmsplugin.c:445:19 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2_plugin.h"

static cmsUInt32Number MockRead(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    FILE* file = (FILE*)iohandler->stream;
    return fread(Buffer, size, count, file);
}

static cmsBool MockSeek(struct _cms_io_handler* iohandler, cmsUInt32Number offset) {
    FILE* file = (FILE*)iohandler->stream;
    return fseek(file, offset, SEEK_SET) == 0;
}

static cmsBool MockClose(struct _cms_io_handler* iohandler) {
    FILE* file = (FILE*)iohandler->stream;
    return fclose(file) == 0;
}

static cmsUInt32Number MockTell(struct _cms_io_handler* iohandler) {
    FILE* file = (FILE*)iohandler->stream;
    return (cmsUInt32Number)ftell(file);
}

static cmsBool MockWrite(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer) {
    FILE* file = (FILE*)iohandler->stream;
    return fwrite(Buffer, size, 1, file) == 1;
}

static cmsIOHANDLER* CreateMockIOHandler(const uint8_t* Data, size_t Size) {
    cmsIOHANDLER* io = (cmsIOHANDLER*)malloc(sizeof(cmsIOHANDLER));
    if (!io) return NULL;

    FILE* file = fopen("./dummy_file", "wb+");
    if (!file) {
        free(io);
        return NULL;
    }

    fwrite(Data, 1, Size, file);
    rewind(file);

    io->stream = file;
    io->Read = MockRead;
    io->Seek = MockSeek;
    io->Close = MockClose;
    io->Tell = MockTell;
    io->Write = MockWrite;

    return io;
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data

    cmsIOHANDLER* io = CreateMockIOHandler(Data, Size);
    if (!io) return 0;

    cmsFloat32Number float32Num;
    cmsUInt8Number uint8Num;
    cmsUInt32Number uint32Num = 0;

    // Fuzz _cmsReadFloat32Number
    _cmsReadFloat32Number(io, &float32Num);

    // Fuzz _cmsWriteAlignment
    _cmsWriteAlignment(io);

    // Fuzz _cmsReadUInt8Number
    _cmsReadUInt8Number(io, &uint8Num);

    // Fuzz _cmsWriteUInt32Number
    _cmsWriteUInt32Number(io, uint32Num);

    // Fuzz _cmsWriteUInt8Number
    _cmsWriteUInt8Number(io, uint8Num);

    // Fuzz _cmsReadAlignment
    _cmsReadAlignment(io);

    io->Close(io);
    free(io);

    return 0;
}