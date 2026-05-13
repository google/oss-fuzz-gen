// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDoTransformStride at cmsxform.c:211:16 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsGetTransformOutputFormat at cmsxform.c:1437:27 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateProofingTransform at cmsxform.c:1398:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsGetTransformInputFormat at cmsxform.c:1429:27 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDoTransform at cmsxform.c:192:16 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "lcms2.h"

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile for testing
    return cmsCreate_sRGBProfile();
}

static void fuzz_cmsCreateMultiprofileTransform(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    cmsUInt32Number nProfiles = Data[0] % 256; // 1 to 255 profiles
    cmsHPROFILE hProfiles[255];
    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        hProfiles[i] = createDummyProfile();
    }

    cmsUInt32Number InputFormat = (Size > 1) ? Data[1] : 0;
    cmsUInt32Number OutputFormat = (Size > 2) ? Data[2] : 0;
    cmsUInt32Number Intent = (Size > 3) ? Data[3] : 0;
    cmsUInt32Number dwFlags = (Size > 4) ? Data[4] : 0;

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(hProfiles, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(hProfiles[i]);
    }
}

static void fuzz_cmsCreateProofingTransform(const uint8_t *Data, size_t Size) {
    if (Size < 3) return;

    cmsHPROFILE Input = createDummyProfile();
    cmsHPROFILE Output = createDummyProfile();
    cmsHPROFILE Proofing = createDummyProfile();

    cmsUInt32Number InputFormat = Data[0];
    cmsUInt32Number OutputFormat = Data[1];
    cmsUInt32Number Intent = Data[2];
    cmsUInt32Number ProofingIntent = (Size > 3) ? Data[3] : 0;
    cmsUInt32Number dwFlags = (Size > 4) ? Data[4] : 0;

    cmsHTRANSFORM transform = cmsCreateProofingTransform(Input, InputFormat, Output, OutputFormat, Proofing, Intent, ProofingIntent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(Input);
    cmsCloseProfile(Output);
    cmsCloseProfile(Proofing);
}

static void fuzz_cmsGetTransformInputFormat(const uint8_t *Data, size_t Size) {
    if (Size < 5) return;

    cmsHPROFILE hProfiles[2];
    hProfiles[0] = createDummyProfile();
    hProfiles[1] = createDummyProfile();

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(hProfiles, 2, Data[0], Data[1], Data[2], Data[3]);

    if (transform) {
        cmsUInt32Number inputFormat = cmsGetTransformInputFormat(transform);
        (void)inputFormat; // Suppress unused variable warning
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(hProfiles[0]);
    cmsCloseProfile(hProfiles[1]);
}

static void fuzz_cmsDoTransform(const uint8_t *Data, size_t Size) {
    if (Size < 6) return;

    cmsHPROFILE hProfiles[2];
    hProfiles[0] = createDummyProfile();
    hProfiles[1] = createDummyProfile();

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(hProfiles, 2, Data[0], Data[1], Data[2], Data[3]);

    if (transform) {
        uint8_t inputBuffer[256] = {0};
        uint8_t outputBuffer[256] = {0};
        cmsDoTransform(transform, inputBuffer, outputBuffer, Size > 5 ? Data[5] : 0);
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(hProfiles[0]);
    cmsCloseProfile(hProfiles[1]);
}

static void fuzz_cmsDoTransformStride(const uint8_t *Data, size_t Size) {
    if (Size < 7) return;

    cmsHPROFILE hProfiles[2];
    hProfiles[0] = createDummyProfile();
    hProfiles[1] = createDummyProfile();

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(hProfiles, 2, Data[0], Data[1], Data[2], Data[3]);

    if (transform) {
        uint8_t inputBuffer[256] = {0};
        uint8_t outputBuffer[256] = {0};
        cmsDoTransformStride(transform, inputBuffer, outputBuffer, Size > 5 ? Data[5] : 0, Size > 6 ? Data[6] : 0);
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(hProfiles[0]);
    cmsCloseProfile(hProfiles[1]);
}

static void fuzz_cmsGetTransformOutputFormat(const uint8_t *Data, size_t Size) {
    if (Size < 5) return;

    cmsHPROFILE hProfiles[2];
    hProfiles[0] = createDummyProfile();
    hProfiles[1] = createDummyProfile();

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(hProfiles, 2, Data[0], Data[1], Data[2], Data[3]);

    if (transform) {
        cmsUInt32Number outputFormat = cmsGetTransformOutputFormat(transform);
        (void)outputFormat; // Suppress unused variable warning
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(hProfiles[0]);
    cmsCloseProfile(hProfiles[1]);
}

int LLVMFuzzerTestOneInput_146(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateMultiprofileTransform(Data, Size);
    fuzz_cmsCreateProofingTransform(Data, Size);
    fuzz_cmsGetTransformInputFormat(Data, Size);
    fuzz_cmsDoTransform(Data, Size);
    fuzz_cmsDoTransformStride(Data, Size);
    fuzz_cmsGetTransformOutputFormat(Data, Size);
    return 0;
}