// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromMem at cmsio0.c:1296:23 in lcms2.h
// cmsGetTagCount at cmsio0.c:581:26 in lcms2.h
// cmsGetTagSignature at cmsio0.c:590:27 in lcms2.h
// cmsReadRawTag at cmsio0.c:1913:27 in lcms2.h
// cmsReadRawTag at cmsio0.c:1913:27 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static cmsHPROFILE createProfileFromMemory(const uint8_t *Data, size_t Size) {
    return cmsOpenProfileFromMem(Data, Size);
}

static void fuzzCmsFunctions(cmsHPROFILE hProfile) {
    if (!hProfile) return;

    // Get the number of tags in the profile
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount <= 0) return;

    // Iterate over each tag and attempt to read it
    for (cmsUInt32Number i = 0; i < (cmsUInt32Number)tagCount; i++) {
        // Get the tag signature
        cmsTagSignature tagSig = cmsGetTagSignature(hProfile, i);
        if (tagSig == 0) continue;

        // Try to read the raw tag data
        cmsUInt32Number bufferSize = 0;
        cmsReadRawTag(hProfile, tagSig, NULL, 0); // First call to get buffer size

        if (bufferSize > 0) {
            void *buffer = malloc(bufferSize);
            if (buffer) {
                cmsReadRawTag(hProfile, tagSig, buffer, bufferSize);
                free(buffer);
            }
        }
    }
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    cmsHPROFILE hProfile = createProfileFromMemory(Data, Size);
    if (hProfile) {
        fuzzCmsFunctions(hProfile);
        cmsCloseProfile(hProfile);
    }
    return 0;
}