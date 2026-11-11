// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDoTransformStride at cmsxform.c:211:16 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateProofingTransform at cmsxform.c:1398:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetTransformInputFormat at cmsxform.c:1429:27 in lcms2.h
// cmsGetTransformOutputFormat at cmsxform.c:1437:27 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDoTransform at cmsxform.c:192:16 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

static cmsHPROFILE create_dummy_profile() {
    // Create a dummy profile; in real scenarios, this would be loaded from actual data
    return cmsCreate_sRGBProfile();
}

static void fuzz_cmsCreateMultiprofileTransform(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    cmsUInt32Number nProfiles = Data[0] % 256;
    cmsHPROFILE *profiles = malloc(nProfiles * sizeof(cmsHPROFILE));
    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        profiles[i] = create_dummy_profile();
    }

    cmsUInt32Number InputFormat = 0;
    cmsUInt32Number OutputFormat = 0;
    cmsUInt32Number Intent = 0;
    cmsUInt32Number dwFlags = 0;

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(profiles[i]);
    }
    free(profiles);
}

static void fuzz_cmsCreateProofingTransform(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    cmsHPROFILE Input = create_dummy_profile();
    cmsHPROFILE Output = create_dummy_profile();
    cmsHPROFILE Proofing = create_dummy_profile();

    cmsUInt32Number InputFormat = 0;
    cmsUInt32Number OutputFormat = 0;
    cmsUInt32Number Intent = 0;
    cmsUInt32Number ProofingIntent = 0;
    cmsUInt32Number dwFlags = 0;

    cmsHTRANSFORM transform = cmsCreateProofingTransform(Input, InputFormat, Output, OutputFormat, Proofing, Intent, ProofingIntent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(Input);
    cmsCloseProfile(Output);
    cmsCloseProfile(Proofing);
}

static void fuzz_cmsGetTransformFormats(const uint8_t *Data, size_t Size) {
    cmsHTRANSFORM transform = NULL;

    if (Size > 0) {
        cmsHPROFILE profiles[1] = { create_dummy_profile() };
        transform = cmsCreateMultiprofileTransform(profiles, 1, 0, 0, 0, 0);
        cmsCloseProfile(profiles[0]);
    }

    cmsUInt32Number inputFormat = cmsGetTransformInputFormat(transform);
    cmsUInt32Number outputFormat = cmsGetTransformOutputFormat(transform);

    if (transform) {
        cmsDeleteTransform(transform);
    }
}

static void fuzz_cmsDoTransform(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    cmsHPROFILE profiles[1] = { create_dummy_profile() };
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, 1, 0, 0, 0, 0);

    if (transform) {
        uint8_t *inputBuffer = malloc(Size);
        uint8_t *outputBuffer = malloc(Size);
        memcpy(inputBuffer, Data, Size);

        cmsDoTransform(transform, inputBuffer, outputBuffer, (cmsUInt32Number)Size);

        free(inputBuffer);
        free(outputBuffer);
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(profiles[0]);
}

static void fuzz_cmsDoTransformStride(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    cmsHPROFILE profiles[1] = { create_dummy_profile() };
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, 1, 0, 0, 0, 0);

    if (transform) {
        uint8_t *inputBuffer = malloc(Size);
        uint8_t *outputBuffer = malloc(Size);
        memcpy(inputBuffer, Data, Size);

        cmsDoTransformStride(transform, inputBuffer, outputBuffer, (cmsUInt32Number)Size, 1);

        free(inputBuffer);
        free(outputBuffer);
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(profiles[0]);
}

int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateMultiprofileTransform(Data, Size);
    fuzz_cmsCreateProofingTransform(Data, Size);
    fuzz_cmsGetTransformFormats(Data, Size);
    fuzz_cmsDoTransform(Data, Size);
    fuzz_cmsDoTransformStride(Data, Size);
    return 0;
}