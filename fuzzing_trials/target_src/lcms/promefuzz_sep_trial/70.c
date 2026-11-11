// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsWrite15Fixed16Number at cmsplugin.c:337:20 in lcms2_plugin.h
// _cms15Fixed16toDouble at cmsplugin.c:377:28 in lcms2_plugin.h
// cmsSetAdaptationStateTHR at cmsxform.c:57:28 in lcms2.h
// _cmsRead15Fixed16Number at cmsplugin.c:224:20 in lcms2_plugin.h
// cmsSetAdaptationState at cmsxform.c:77:28 in lcms2.h
// _cmsDoubleTo15Fixed16 at cmsplugin.c:383:31 in lcms2_plugin.h
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

static cmsUInt32Number DummyRead(struct _cms_io_handler* iohandler, void *Buffer, cmsUInt32Number size, cmsUInt32Number count) {
    return fread(Buffer, size, count, (FILE*)iohandler->stream);
}

static cmsBool DummyWrite(struct _cms_io_handler* iohandler, cmsUInt32Number size, const void* Buffer) {
    return fwrite(Buffer, size, 1, (FILE*)iohandler->stream) == 1;
}

static cmsBool DummySeek(struct _cms_io_handler* iohandler, cmsUInt32Number offset) {
    return fseek((FILE*)iohandler->stream, offset, SEEK_SET) == 0;
}

static cmsUInt32Number DummyTell(struct _cms_io_handler* iohandler) {
    return ftell((FILE*)iohandler->stream);
}

static cmsBool DummyClose(struct _cms_io_handler* iohandler) {
    return fclose((FILE*)iohandler->stream) == 0;
}

int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) + sizeof(cmsS15Fixed16Number)) {
        return 0;
    }

    cmsIOHANDLER ioHandler;
    cmsFloat64Number floatInput;
    cmsS15Fixed16Number fixedInput;
    cmsFloat64Number result;
    cmsBool success;
    cmsContext context = NULL;

    FILE* dummyFile = fopen("./dummy_file", "wb+");
    if (!dummyFile) {
        return 0;
    }

    ioHandler.stream = dummyFile;
    ioHandler.Read = DummyRead;
    ioHandler.Write = DummyWrite;
    ioHandler.Seek = DummySeek;
    ioHandler.Tell = DummyTell;
    ioHandler.Close = DummyClose;

    memcpy(&floatInput, Data, sizeof(cmsFloat64Number));
    memcpy(&fixedInput, Data + sizeof(cmsFloat64Number), sizeof(cmsS15Fixed16Number));

    // Test _cmsWrite15Fixed16Number
    success = _cmsWrite15Fixed16Number(&ioHandler, floatInput);
    if (!success) {
        fclose(dummyFile);
        return 0;
    }

    // Test _cms15Fixed16toDouble
    result = _cms15Fixed16toDouble(fixedInput);

    // Test cmsSetAdaptationStateTHR
    result = cmsSetAdaptationStateTHR(context, floatInput);

    // Test _cmsRead15Fixed16Number
    ioHandler.Seek(&ioHandler, 0);
    success = _cmsRead15Fixed16Number(&ioHandler, &result);

    // Test cmsSetAdaptationState
    result = cmsSetAdaptationState(floatInput);

    // Test _cmsDoubleTo15Fixed16
    fixedInput = _cmsDoubleTo15Fixed16(floatInput);

    fclose(dummyFile);
    return 0;
}