// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateBCHSWabstractProfileTHR at cmsvirt.c:861:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateExtendedTransform at cmsxform.c:1123:25 in lcms2.h
// cmsTransform2DeviceLink at cmsvirt.c:1194:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCreateProofingTransform at cmsxform.c:1398:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCreateMultiprofileTransformTHR at cmsxform.c:1286:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCreateBCHSWabstractProfile at cmsvirt.c:946:32 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsHPROFILE create_dummy_profile() {
    return cmsCreate_sRGBProfile();
}

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 61) {
        return 0;
    }

    cmsContext context = NULL;
    cmsUInt32Number nProfiles = Data[0] % 255 + 1;
    cmsUInt32Number inputFormat = *(cmsUInt32Number *)(Data + 1);
    cmsUInt32Number outputFormat = *(cmsUInt32Number *)(Data + 5);
    cmsUInt32Number intent = *(cmsUInt32Number *)(Data + 9);
    cmsUInt32Number flags = *(cmsUInt32Number *)(Data + 13);
    cmsFloat64Number version = *(cmsFloat64Number *)(Data + 17);

    cmsHPROFILE profiles[255];
    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        profiles[i] = create_dummy_profile();
    }

    cmsBool BPC[255] = {0};
    cmsUInt32Number Intents[255] = {0};
    cmsFloat64Number AdaptationStates[255] = {0};

    cmsHTRANSFORM transform = cmsCreateExtendedTransform(
        context,
        nProfiles,
        profiles,
        BPC,
        Intents,
        AdaptationStates,
        NULL,
        0,
        inputFormat,
        outputFormat,
        flags
    );

    if (transform) {
        cmsHPROFILE deviceLink = cmsTransform2DeviceLink(transform, version, flags);
        if (deviceLink) {
            cmsCloseProfile(deviceLink);
        }
        cmsDeleteTransform(transform);
    }

    cmsHTRANSFORM proofingTransform = cmsCreateProofingTransform(
        profiles[0],
        inputFormat,
        profiles[1 % nProfiles],
        outputFormat,
        profiles[2 % nProfiles],
        intent,
        intent,
        flags
    );

    if (proofingTransform) {
        cmsDeleteTransform(proofingTransform);
    }

    cmsHTRANSFORM multiprofileTransform = cmsCreateMultiprofileTransformTHR(
        context,
        profiles,
        nProfiles,
        inputFormat,
        outputFormat,
        intent,
        flags
    );

    if (multiprofileTransform) {
        cmsDeleteTransform(multiprofileTransform);
    }

    cmsHPROFILE abstractProfile = cmsCreateBCHSWabstractProfile(
        nProfiles,
        *(cmsFloat64Number *)(Data + 21),
        *(cmsFloat64Number *)(Data + 29),
        *(cmsFloat64Number *)(Data + 37),
        *(cmsFloat64Number *)(Data + 45),
        *(cmsUInt32Number *)(Data + 53),
        *(cmsUInt32Number *)(Data + 57)
    );

    if (abstractProfile) {
        cmsCloseProfile(abstractProfile);
    }

    cmsHPROFILE abstractProfileTHR = cmsCreateBCHSWabstractProfileTHR(
        context,
        nProfiles,
        *(cmsFloat64Number *)(Data + 21),
        *(cmsFloat64Number *)(Data + 29),
        *(cmsFloat64Number *)(Data + 37),
        *(cmsFloat64Number *)(Data + 45),
        *(cmsUInt32Number *)(Data + 53),
        *(cmsUInt32Number *)(Data + 57)
    );

    if (abstractProfileTHR) {
        cmsCloseProfile(abstractProfileTHR);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(profiles[i]);
    }

    return 0;
}