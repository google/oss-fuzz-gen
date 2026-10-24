// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsIsCLUT at cmsio1.c:830:20 in lcms2.h
// cmsIsIntentSupported at cmsio1.c:864:20 in lcms2.h
// cmsFormatterForColorspaceOfProfile at cmspack.c:4025:27 in lcms2.h
// cmsCreateTransform at cmsxform.c:1355:32 in lcms2.h
// cmsChangeBuffersFormat at cmsxform.c:1446:19 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCreateProofingTransform at cmsxform.c:1398:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

static cmsHPROFILE createDummyProfile() {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;

    // Writing minimal ICC profile data to the file
    unsigned char profileData[] = {
        0x00, 0x00, 0x02, 0x0C, // Profile size
        0x61, 0x63, 0x73, 0x70, // Preferred CMM type
        0x02, 0x10, 0x00, 0x00, // Version
        0x6D, 0x6E, 0x74, 0x72, // Profile/Device class
        0x52, 0x47, 0x42, 0x20, // Data color space
        0x58, 0x59, 0x5A, 0x20, // PCS
        0x00, 0x00, 0x00, 0x00, // Date/time
        0x00, 0x00, 0x00, 0x00, // Date/time
        0x00, 0x00, 0x00, 0x00, // Date/time
        0x61, 0x63, 0x73, 0x70, // Profile signature
        0x00, 0x00, 0x00, 0x00, // Platform
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Device manufacturer
        0x00, 0x00, 0x00, 0x00, // Device model
        0x00, 0x00, 0x00, 0x00, // Device attributes
        0x00, 0x00, 0x00, 0x00, // Device attributes
        0x00, 0x00, 0x00, 0x00, // Rendering intent
        0x00, 0x00, 0x00, 0x00, // Illuminant
        0x00, 0x00, 0x00, 0x00, // Illuminant
        0x00, 0x00, 0x00, 0x00, // Illuminant
        0x00, 0x00, 0x00, 0x00, // Creator
        0x00, 0x00, 0x00, 0x00  // Profile ID
    };
    fwrite(profileData, sizeof(profileData), 1, file);
    fclose(file);

    return cmsOpenProfileFromFile("./dummy_file", "r");
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    cmsHPROFILE hProfile = createDummyProfile();
    if (!hProfile) return 0;

    cmsUInt32Number Intent = Data[0];
    cmsUInt32Number UsedDirection = Data[1];
    cmsUInt32Number nBytes = Data[2];
    cmsBool lIsFloat = Data[3] % 2;

    cmsIsCLUT(hProfile, Intent, UsedDirection);
    cmsIsIntentSupported(hProfile, Intent, UsedDirection);
    cmsFormatterForColorspaceOfProfile(hProfile, nBytes, lIsFloat);

    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, Intent, hProfile, Intent, Intent, 0);
    if (hTransform) {
        cmsChangeBuffersFormat(hTransform, Intent, UsedDirection);
        cmsDeleteTransform(hTransform);
    }

    cmsHTRANSFORM hProofingTransform = cmsCreateProofingTransform(hProfile, Intent, hProfile, Intent, hProfile, Intent, UsedDirection, 0);
    if (hProofingTransform) {
        cmsDeleteTransform(hProofingTransform);
    }

    cmsCloseProfile(hProfile);
    return 0;
}