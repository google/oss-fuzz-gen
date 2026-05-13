// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsGetTagCount at cmsio0.c:581:26 in lcms2.h
// cmsGetTagSignature at cmsio0.c:590:27 in lcms2.h
// cmsReadTag at cmsio0.c:1639:17 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

static cmsHPROFILE LoadProfileFromData(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;

    fwrite(Data, 1, Size, file);
    fclose(file);

    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    return hProfile;
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    cmsHPROFILE hProfile = LoadProfileFromData(Data, Size);
    if (!hProfile) return 0;

    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    for (cmsUInt32Number i = 0; i < tagCount; i++) {
        cmsTagSignature sig = cmsGetTagSignature(hProfile, i);
        if (sig != 0) {
            void *tagData = cmsReadTag(hProfile, sig);
            // Optionally do something with tagData
        }
    }

    cmsCloseProfile(hProfile);
    return 0;
}