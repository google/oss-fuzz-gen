// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreateContext at cmsplugin.c:824:22 in lcms2.h
// _cmsMallocZero at cmserr.c:272:17 in lcms2_plugin.h
// _cmsFree at cmserr.c:293:16 in lcms2_plugin.h
// cmsAllocProfileSequenceDescription at cmsnamed.c:985:19 in lcms2.h
// cmsFreeProfileSequenceDescription at cmsnamed.c:1017:16 in lcms2.h
// _cmsDupMem at cmserr.c:302:17 in lcms2_plugin.h
// _cmsFree at cmserr.c:293:16 in lcms2_plugin.h
// _cmsMalloc at cmserr.c:265:17 in lcms2_plugin.h
// _cmsFree at cmserr.c:293:16 in lcms2_plugin.h
// _cmsMalloc at cmserr.c:265:17 in lcms2_plugin.h
// _cmsRealloc at cmserr.c:286:17 in lcms2_plugin.h
// _cmsFree at cmserr.c:293:16 in lcms2_plugin.h
// _cmsFree at cmserr.c:293:16 in lcms2_plugin.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
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

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    cmsContext ctx = cmsCreateContext(NULL, NULL);
    if (!ctx) return 0;

    // Test _cmsMallocZero
    cmsUInt32Number size = *(cmsUInt32Number *)Data;
    void *zeroMem = _cmsMallocZero(ctx, size);
    if (zeroMem) {
        _cmsFree(ctx, zeroMem);
    }

    // Test cmsAllocProfileSequenceDescription
    cmsUInt32Number nProfiles = Data[3] % 256; // Limit to 255
    cmsSEQ *seqDesc = cmsAllocProfileSequenceDescription(ctx, nProfiles);
    if (seqDesc) {
        cmsFreeProfileSequenceDescription(seqDesc);
    }

    // Test _cmsDupMem
    if (Size > 4) {
        const void *orgMem = Data + 4;
        size_t orgSize = Size - 4;
        void *dupMem = _cmsDupMem(ctx, orgMem, (cmsUInt32Number)orgSize);
        if (dupMem) {
            _cmsFree(ctx, dupMem);
        }
    }

    // Test _cmsMalloc
    void *mallocMem = _cmsMalloc(ctx, size);
    if (mallocMem) {
        _cmsFree(ctx, mallocMem);
    }

    // Test _cmsRealloc
    void *reallocMem = _cmsMalloc(ctx, size);
    if (reallocMem) {
        void *newMem = _cmsRealloc(ctx, reallocMem, size * 2);
        if (newMem) {
            _cmsFree(ctx, newMem);
        } else {
            _cmsFree(ctx, reallocMem);
        }
    }

    cmsDeleteContext(ctx);
    return 0;
}