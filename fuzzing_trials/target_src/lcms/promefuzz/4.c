// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsGetPostScriptCRD at cmsps2.c:1584:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1668:20 in lcms2.h
// _cmsMalloc at cmserr.c:308:17 in lcms2_plugin.h
// cmsCloseProfile at cmsio0.c:1668:20 in lcms2.h
// cmsGetPostScriptCRD at cmsps2.c:1584:27 in lcms2.h
// _cmsFree at cmserr.c:336:16 in lcms2_plugin.h
// cmsCloseProfile at cmsio0.c:1668:20 in lcms2.h
// _cmsFree at cmserr.c:336:16 in lcms2_plugin.h
// cmsCloseProfile at cmsio0.c:1668:20 in lcms2.h
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

static cmsHPROFILE create_dummy_profile() {
    // Create a dummy profile for testing purposes
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    return hProfile;
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    cmsContext context = NULL; // Use default context
    cmsHPROFILE hProfile = create_dummy_profile();
    cmsUInt32Number intent = 0; // Default rendering intent
    cmsUInt32Number flags = 0; // Default flags
    cmsUInt32Number bufferSize = 1024; // Arbitrary buffer size for CRD
    void* buffer = NULL;

    if (hProfile == NULL) {
        return 0;
    }

    // First call to cmsGetPostScriptCRD with buffer = NULL to get required size
    cmsUInt32Number crdSize = cmsGetPostScriptCRD(context, hProfile, intent, flags, NULL, 0);
    if (crdSize == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Allocate memory using _cmsMalloc
    buffer = _cmsMalloc(context, crdSize);
    if (buffer == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Second call to cmsGetPostScriptCRD with allocated buffer
    cmsUInt32Number bytesWritten = cmsGetPostScriptCRD(context, hProfile, intent, flags, buffer, crdSize);
    if (bytesWritten == 0) {
        _cmsFree(context, buffer);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Free the allocated buffer
    _cmsFree(context, buffer);
    cmsCloseProfile(hProfile);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
