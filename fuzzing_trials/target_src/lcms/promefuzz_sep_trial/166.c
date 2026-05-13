// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsGetHeaderManufacturer at cmsio0.c:1009:27 in lcms2.h
// cmsIsIntentSupported at cmsio1.c:864:20 in lcms2.h
// cmsGetHeaderCreator at cmsio0.c:1021:27 in lcms2.h
// cmsGetHeaderFlags at cmsio0.c:997:27 in lcms2.h
// cmsFormatterForColorspaceOfProfile at cmspack.c:4025:27 in lcms2.h
// cmsFormatterForPCSOfProfile at cmspack.c:4044:27 in lcms2.h
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

static cmsHPROFILE openProfileFromData(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(data, 1, size, file);
    fclose(file);

    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    return hProfile;
}

static void fuzz_cmsGetHeaderManufacturer(cmsHPROFILE hProfile) {
    cmsUInt32Number manufacturer = cmsGetHeaderManufacturer(hProfile);
    (void)manufacturer; // Suppress unused variable warning
}

static void fuzz_cmsIsIntentSupported(cmsHPROFILE hProfile) {
    cmsUInt32Number intents[] = { INTENT_PERCEPTUAL, INTENT_RELATIVE_COLORIMETRIC, INTENT_SATURATION, INTENT_ABSOLUTE_COLORIMETRIC };
    cmsUInt32Number directions[] = { LCMS_USED_AS_INPUT, LCMS_USED_AS_OUTPUT };

    for (size_t i = 0; i < sizeof(intents) / sizeof(intents[0]); ++i) {
        for (size_t j = 0; j < sizeof(directions) / sizeof(directions[0]); ++j) {
            cmsBool supported = cmsIsIntentSupported(hProfile, intents[i], directions[j]);
            (void)supported; // Suppress unused variable warning
        }
    }
}

static void fuzz_cmsGetHeaderCreator(cmsHPROFILE hProfile) {
    cmsUInt32Number creator = cmsGetHeaderCreator(hProfile);
    (void)creator; // Suppress unused variable warning
}

static void fuzz_cmsGetHeaderFlags(cmsHPROFILE hProfile) {
    cmsUInt32Number flags = cmsGetHeaderFlags(hProfile);
    (void)flags; // Suppress unused variable warning
}

static void fuzz_cmsFormatterForColorspaceOfProfile(cmsHPROFILE hProfile) {
    cmsUInt32Number bytesPerChannel[] = { 1, 2 };
    cmsBool isFloat[] = { 0, 1 };

    for (size_t i = 0; i < sizeof(bytesPerChannel) / sizeof(bytesPerChannel[0]); ++i) {
        for (size_t j = 0; j < sizeof(isFloat) / sizeof(isFloat[0]); ++j) {
            cmsUInt32Number formatter = cmsFormatterForColorspaceOfProfile(hProfile, bytesPerChannel[i], isFloat[j]);
            (void)formatter; // Suppress unused variable warning
        }
    }
}

static void fuzz_cmsFormatterForPCSOfProfile(cmsHPROFILE hProfile) {
    cmsUInt32Number bytesPerChannel[] = { 1, 2 };
    cmsBool isFloat[] = { 0, 1 };

    for (size_t i = 0; i < sizeof(bytesPerChannel) / sizeof(bytesPerChannel[0]); ++i) {
        for (size_t j = 0; j < sizeof(isFloat) / sizeof(isFloat[0]); ++j) {
            cmsUInt32Number formatter = cmsFormatterForPCSOfProfile(hProfile, bytesPerChannel[i], isFloat[j]);
            (void)formatter; // Suppress unused variable warning
        }
    }
}

int LLVMFuzzerTestOneInput_166(const uint8_t *Data, size_t Size) {
    cmsHPROFILE hProfile = openProfileFromData(Data, Size);
    if (!hProfile) return 0;

    fuzz_cmsGetHeaderManufacturer(hProfile);
    fuzz_cmsIsIntentSupported(hProfile);
    fuzz_cmsGetHeaderCreator(hProfile);
    fuzz_cmsGetHeaderFlags(hProfile);
    fuzz_cmsFormatterForColorspaceOfProfile(hProfile);
    fuzz_cmsFormatterForPCSOfProfile(hProfile);

    cmsCloseProfile(hProfile);
    return 0;
}