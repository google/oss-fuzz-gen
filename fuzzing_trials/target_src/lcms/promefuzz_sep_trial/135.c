// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsReadUInt32Number at cmsplugin.c:156:20 in lcms2_plugin.h
// _cmsWriteUInt64Number at cmsplugin.c:324:20 in lcms2_plugin.h
// _cmsWriteUInt32Number at cmsplugin.c:295:20 in lcms2_plugin.h
// _cmsAdjustEndianess32 at cmsplugin.c:58:28 in lcms2_plugin.h
// _cmsWriteTypeBase at cmsplugin.c:434:20 in lcms2_plugin.h
// _cmsWriteXYZNumber at cmsplugin.c:350:20 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lcms2_plugin.h"

static cmsUInt32Number DummyRead(cmsIOHANDLER* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    return fread(Buffer, size, count, (FILE*) iohandler->stream);
}

static cmsBool DummyWrite(cmsIOHANDLER* iohandler, cmsUInt32Number size, const void* Buffer) {
    return fwrite(Buffer, size, 1, (FILE*) iohandler->stream) == 1;
}

static cmsBool DummySeek(cmsIOHANDLER* iohandler, cmsUInt32Number offset) {
    return fseek((FILE*) iohandler->stream, offset, SEEK_SET) == 0;
}

static cmsBool DummyClose(cmsIOHANDLER* iohandler) {
    return fclose((FILE*) iohandler->stream) == 0;
}

static cmsUInt32Number DummyTell(cmsIOHANDLER* iohandler) {
    return (cmsUInt32Number) ftell((FILE*) iohandler->stream);
}

int LLVMFuzzerTestOneInput_135(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return 0;

    FILE* file = fopen("./dummy_file", "wb+");
    if (!file) return 0;

    cmsIOHANDLER ioHandler;
    ioHandler.stream = file;
    ioHandler.Read = DummyRead;
    ioHandler.Write = DummyWrite;
    ioHandler.Seek = DummySeek;
    ioHandler.Close = DummyClose;
    ioHandler.Tell = DummyTell;

    // Test _cmsReadUInt32Number
    cmsUInt32Number num32;
    if (Size >= sizeof(cmsUInt32Number)) {
        fwrite(Data, sizeof(cmsUInt32Number), 1, file);
        rewind(file);
        _cmsReadUInt32Number(&ioHandler, &num32);
    }

    // Test _cmsWriteUInt64Number
    cmsUInt64Number num64;
    if (Size >= sizeof(cmsUInt64Number)) {
        memcpy(&num64, Data, sizeof(cmsUInt64Number));
        _cmsWriteUInt64Number(&ioHandler, &num64);
    }

    // Test _cmsWriteUInt32Number
    if (Size >= sizeof(cmsUInt32Number)) {
        memcpy(&num32, Data, sizeof(cmsUInt32Number));
        _cmsWriteUInt32Number(&ioHandler, num32);
    }

    // Test _cmsAdjustEndianess32
    if (Size >= sizeof(cmsUInt32Number)) {
        memcpy(&num32, Data, sizeof(cmsUInt32Number));
        _cmsAdjustEndianess32(num32);
    }

    // Test _cmsWriteTypeBase
    cmsTagTypeSignature sig;
    if (Size >= sizeof(cmsTagTypeSignature)) {
        memcpy(&sig, Data, sizeof(cmsTagTypeSignature));
        _cmsWriteTypeBase(&ioHandler, sig);
    }

    // Test _cmsWriteXYZNumber
    cmsCIEXYZ xyz;
    if (Size >= sizeof(cmsCIEXYZ)) {
        memcpy(&xyz, Data, sizeof(cmsCIEXYZ));
        _cmsWriteXYZNumber(&ioHandler, &xyz);
    }

    fclose(file);
    return 0;
}