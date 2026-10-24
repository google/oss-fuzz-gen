// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreateTransform at cmsxform.c:1355:32 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetSupportedIntentsTHR at cmscnvrt.c:1157:27 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCreateMultiprofileTransformTHR at cmsxform.c:1286:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateTransformTHR at cmsxform.c:1338:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateProofingTransformTHR at cmsxform.c:1366:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateExtendedTransform at cmsxform.c:1123:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile for testing
    return cmsCreate_sRGBProfile();
}

static void fuzz_cmsCreateTransformTHR(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 4) return;

    cmsContext ContextID = NULL;
    cmsHPROFILE Input = createDummyProfile();
    cmsHPROFILE Output = createDummyProfile();
    cmsUInt32Number InputFormat = *(cmsUInt32Number*)Data;
    cmsUInt32Number OutputFormat = *(cmsUInt32Number*)(Data + sizeof(cmsUInt32Number));
    cmsUInt32Number Intent = *(cmsUInt32Number*)(Data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)(Data + 3 * sizeof(cmsUInt32Number));

    cmsHTRANSFORM transform = cmsCreateTransformTHR(ContextID, Input, InputFormat, Output, OutputFormat, Intent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(Input);
    cmsCloseProfile(Output);
}

static void fuzz_cmsCreateProofingTransformTHR(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 6) return;

    cmsContext ContextID = NULL;
    cmsHPROFILE Input = createDummyProfile();
    cmsHPROFILE Output = createDummyProfile();
    cmsHPROFILE Proofing = createDummyProfile();
    cmsUInt32Number InputFormat = *(cmsUInt32Number*)Data;
    cmsUInt32Number OutputFormat = *(cmsUInt32Number*)(Data + sizeof(cmsUInt32Number));
    cmsUInt32Number Intent = *(cmsUInt32Number*)(Data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number ProofingIntent = *(cmsUInt32Number*)(Data + 3 * sizeof(cmsUInt32Number));
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)(Data + 4 * sizeof(cmsUInt32Number));

    cmsHTRANSFORM transform = cmsCreateProofingTransformTHR(ContextID, Input, InputFormat, Output, OutputFormat, Proofing, Intent, ProofingIntent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(Input);
    cmsCloseProfile(Output);
    cmsCloseProfile(Proofing);
}

static void fuzz_cmsCreateExtendedTransform(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 5) return;

    cmsContext ContextID = NULL;
    cmsUInt32Number nProfiles = *(cmsUInt32Number*)Data % 255 + 1;
    cmsHPROFILE hProfiles[255];
    cmsBool BPC[255];
    cmsUInt32Number Intents[255];
    cmsFloat64Number AdaptationStates[255];
    cmsUInt32Number InputFormat = *(cmsUInt32Number*)(Data + sizeof(cmsUInt32Number));
    cmsUInt32Number OutputFormat = *(cmsUInt32Number*)(Data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)(Data + 3 * sizeof(cmsUInt32Number));

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        hProfiles[i] = createDummyProfile();
        BPC[i] = *(Data + 4 * sizeof(cmsUInt32Number) + i) % 2;
        Intents[i] = *(cmsUInt32Number*)(Data + 4 * sizeof(cmsUInt32Number) + i * sizeof(cmsUInt32Number));
        AdaptationStates[i] = 1.0;
    }

    cmsHTRANSFORM transform = cmsCreateExtendedTransform(ContextID, nProfiles, hProfiles, BPC, Intents, AdaptationStates, NULL, 0, InputFormat, OutputFormat, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(hProfiles[i]);
    }
}

static void fuzz_cmsCreateTransform(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 4) return;

    cmsHPROFILE Input = createDummyProfile();
    cmsHPROFILE Output = createDummyProfile();
    cmsUInt32Number InputFormat = *(cmsUInt32Number*)Data;
    cmsUInt32Number OutputFormat = *(cmsUInt32Number*)(Data + sizeof(cmsUInt32Number));
    cmsUInt32Number Intent = *(cmsUInt32Number*)(Data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)(Data + 3 * sizeof(cmsUInt32Number));

    cmsHTRANSFORM transform = cmsCreateTransform(Input, InputFormat, Output, OutputFormat, Intent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(Input);
    cmsCloseProfile(Output);
}

static void fuzz_cmsGetSupportedIntentsTHR(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return;

    cmsContext ContextID = NULL;
    cmsUInt32Number nMax = *(cmsUInt32Number*)Data % 10 + 1;
    cmsUInt32Number Codes[10];
    char* Descriptions[10] = {0};

    cmsUInt32Number count = cmsGetSupportedIntentsTHR(ContextID, nMax, Codes, Descriptions);

    for (cmsUInt32Number i = 0; i < count; i++) {
        // Descriptions are not dynamically allocated by the library, so no need to free them.
        Descriptions[i] = NULL;
    }
}

static void fuzz_cmsCreateMultiprofileTransformTHR(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 5) return;

    cmsContext ContextID = NULL;
    cmsUInt32Number nProfiles = *(cmsUInt32Number*)Data % 255 + 1;
    cmsHPROFILE hProfiles[255];
    cmsUInt32Number InputFormat = *(cmsUInt32Number*)(Data + sizeof(cmsUInt32Number));
    cmsUInt32Number OutputFormat = *(cmsUInt32Number*)(Data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number Intent = *(cmsUInt32Number*)(Data + 3 * sizeof(cmsUInt32Number));
    cmsUInt32Number dwFlags = *(cmsUInt32Number*)(Data + 4 * sizeof(cmsUInt32Number));

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        hProfiles[i] = createDummyProfile();
    }

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransformTHR(ContextID, hProfiles, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);

    if (transform) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(hProfiles[i]);
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    fuzz_cmsCreateTransformTHR(Data, Size);
    fuzz_cmsCreateProofingTransformTHR(Data, Size);
    fuzz_cmsCreateExtendedTransform(Data, Size);
    fuzz_cmsCreateTransform(Data, Size);
    fuzz_cmsGetSupportedIntentsTHR(Data, Size);
    fuzz_cmsCreateMultiprofileTransformTHR(Data, Size);
    return 0;
}