// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreateContext at cmsplugin.c:824:22 in lcms2.h
// _cmsCreateMutex at cmserr.c:627:17 in lcms2_plugin.h
// _cmsLockMutex at cmserr.c:646:19 in lcms2_plugin.h
// _cmsUnlockMutex at cmserr.c:655:16 in lcms2_plugin.h
// _cmsDestroyMutex at cmserr.c:636:16 in lcms2_plugin.h
// cmsGetContextUserData at cmsplugin.c:1021:17 in lcms2.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"
#include "lcms2_plugin.h"

static void PrepareDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsContext)) return 0;

    // Assuming a valid context is created by some means
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) return 0;

    void* mtx = _cmsCreateMutex(context);
    if (mtx != NULL) {
        _cmsLockMutex(context, mtx);
        _cmsUnlockMutex(context, mtx);
        _cmsDestroyMutex(context, mtx);
    }

    void* userData = cmsGetContextUserData(context);
    if (userData != NULL) {
        // Do something with userData if needed
    }

    cmsDeleteContext(context);

    // Prepare dummy file if needed for additional testing
    PrepareDummyFile(Data, Size);

    return 0;
}