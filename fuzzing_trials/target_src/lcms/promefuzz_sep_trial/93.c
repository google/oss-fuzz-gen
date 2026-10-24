// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsWriteUInt16Number at cmsplugin.c:268:20 in lcms2_plugin.h
// _cmsWrite15Fixed16Number at cmsplugin.c:337:20 in lcms2_plugin.h
// _cmsWriteUInt64Number at cmsplugin.c:324:20 in lcms2_plugin.h
// _cmsWriteAlignment at cmsplugin.c:462:19 in lcms2_plugin.h
// _cmsReadUInt64Number at cmsplugin.c:206:21 in lcms2_plugin.h
// cmsCloseIOhandler at cmsio0.c:510:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

static cmsUInt32Number DummyReadHandler(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    // Dummy read handler
    return size * count;
}

static cmsBool DummySeekHandler(struct _cms_io_handler* iohandler, cmsUInt32Number offset) {
    // Dummy seek handler
    return TRUE;
}

static cmsBool DummyCloseHandler(struct _cms_io_handler* iohandler) {
    // Dummy close handler
    return TRUE;
}

static cmsUInt32Number DummyTellHandler(struct _cms_io_handler* iohandler) {
    // Dummy tell handler
    return iohandler->UsedSpace;
}

static cmsBool DummyWriteHandler(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer) {
    // Dummy write handler
    iohandler->UsedSpace += size;
    return TRUE;
}

static cmsIOHANDLER* CreateDummyIOHandler() {
    cmsIOHANDLER* handler = (cmsIOHANDLER*)malloc(sizeof(cmsIOHANDLER));
    if (!handler) return NULL;

    handler->stream = NULL;
    handler->ContextID = NULL;
    handler->UsedSpace = 0;
    handler->ReportedSize = 0;
    memset(handler->PhysicalFile, 0, sizeof(handler->PhysicalFile));

    handler->Read = DummyReadHandler;
    handler->Seek = DummySeekHandler;
    handler->Close = DummyCloseHandler;
    handler->Tell = DummyTellHandler;
    handler->Write = DummyWriteHandler;

    return handler;
}

int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt64Number)) return 0;

    cmsIOHANDLER* io = CreateDummyIOHandler();
    if (!io) return 0;

    cmsUInt16Number u16 = *((cmsUInt16Number*)Data);
    cmsFloat64Number f64 = *((cmsFloat64Number*)Data);
    cmsUInt64Number u64 = *((cmsUInt64Number*)Data);

    // Test _cmsWriteUInt16Number
    _cmsWriteUInt16Number(io, u16);

    // Test _cmsWrite15Fixed16Number
    _cmsWrite15Fixed16Number(io, f64);

    // Test _cmsWriteUInt64Number
    _cmsWriteUInt64Number(io, &u64);

    // Test _cmsWriteAlignment
    _cmsWriteAlignment(io);

    // Test _cmsReadUInt64Number
    _cmsReadUInt64Number(io, &u64);

    // Test cmsCloseIOhandler
    cmsCloseIOhandler(io);

    free(io);
    return 0;
}