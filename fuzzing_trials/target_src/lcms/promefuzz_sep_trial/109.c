// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsReadFloat32Number at cmsplugin.c:169:20 in lcms2_plugin.h
// _cmsWriteFloat32Number at cmsplugin.c:309:20 in lcms2_plugin.h
// _cmsWriteAlignment at cmsplugin.c:462:19 in lcms2_plugin.h
// _cmsIOPrintf at cmsplugin.c:482:19 in lcms2_plugin.h
// _cmsReadAlignment at cmsplugin.c:445:19 in lcms2_plugin.h
// cmsCloseIOhandler at cmsio0.c:510:19 in lcms2.h
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
#include "lcms2_plugin.h"

static cmsUInt32Number MockRead(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    // Simulate reading by copying from a dummy buffer
    size_t toRead = size * count;
    if (toRead > iohandler->ReportedSize - iohandler->UsedSpace) {
        toRead = iohandler->ReportedSize - iohandler->UsedSpace;
    }
    memcpy(Buffer, ((uint8_t*)iohandler->stream) + iohandler->UsedSpace, toRead);
    iohandler->UsedSpace += toRead;
    return toRead / size;
}

static cmsBool MockSeek(struct _cms_io_handler* iohandler, cmsUInt32Number offset) {
    if (offset > iohandler->ReportedSize) {
        return FALSE;
    }
    iohandler->UsedSpace = offset;
    return TRUE;
}

static cmsBool MockClose(struct _cms_io_handler* iohandler) {
    free(iohandler->stream);
    return TRUE;
}

static cmsUInt32Number MockTell(struct _cms_io_handler* iohandler) {
    return iohandler->UsedSpace;
}

static cmsBool MockWrite(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer) {
    if (iohandler->UsedSpace + size > iohandler->ReportedSize) {
        return FALSE;
    }
    memcpy(((uint8_t*)iohandler->stream) + iohandler->UsedSpace, Buffer, size);
    iohandler->UsedSpace += size;
    return TRUE;
}

int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    cmsIOHANDLER io;
    io.stream = malloc(Size);
    if (!io.stream) {
        return 0;
    }
    memcpy(io.stream, Data, Size);
    io.ContextID = NULL;
    io.UsedSpace = 0;
    io.ReportedSize = Size;
    io.Read = MockRead;
    io.Seek = MockSeek;
    io.Close = MockClose;
    io.Tell = MockTell;
    io.Write = MockWrite;

    cmsFloat32Number number;

    // Test _cmsReadFloat32Number
    _cmsReadFloat32Number(&io, &number);

    // Test _cmsWriteFloat32Number
    _cmsWriteFloat32Number(&io, number);

    // Test _cmsWriteAlignment
    _cmsWriteAlignment(&io);

    // Test _cmsIOPrintf
    _cmsIOPrintf(&io, "Test format %f", number);

    // Test _cmsReadAlignment
    _cmsReadAlignment(&io);

    // Test cmsCloseIOhandler
    cmsCloseIOhandler(&io);

    return 0;
}