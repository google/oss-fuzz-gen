// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCreateTransform at cmsxform.c:1355:32 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsTransform2DeviceLink at cmsvirt.c:1194:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCreateExtendedTransform at cmsxform.c:1123:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSetProfileVersion at cmsio0.c:1139:17 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateBCHSWabstractProfile at cmsvirt.c:946:32 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSetAdaptationState at cmsxform.c:77:28 in lcms2.h
// cmsCreateBCHSWabstractProfileTHR at cmsvirt.c:861:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile for testing purposes
    return cmsCreate_sRGBProfile();
}

static cmsHTRANSFORM createDummyTransform() {
    cmsHPROFILE hProfiles[2];
    hProfiles[0] = createDummyProfile();
    hProfiles[1] = createDummyProfile();
    cmsHTRANSFORM transform = cmsCreateTransform(hProfiles[0], TYPE_RGB_8, hProfiles[1], TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    cmsCloseProfile(hProfiles[0]);
    cmsCloseProfile(hProfiles[1]);
    return transform;
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number)) return 0;

    // Prepare input data
    cmsFloat64Number version = *(cmsFloat64Number*)Data;
    cmsUInt32Number flags = 0;
    if (Size > sizeof(cmsFloat64Number)) {
        flags = *(cmsUInt32Number*)(Data + sizeof(cmsFloat64Number));
    }

    // Test cmsTransform2DeviceLink
    cmsHTRANSFORM hTransform = createDummyTransform();
    cmsHPROFILE deviceLinkProfile = cmsTransform2DeviceLink(hTransform, version, flags);
    if (deviceLinkProfile) {
        cmsCloseProfile(deviceLinkProfile);
    }
    cmsDeleteTransform(hTransform);

    // Test cmsCreateExtendedTransform
    cmsHPROFILE hProfiles[1];
    hProfiles[0] = createDummyProfile();
    cmsBool BPC[1] = { 0 };
    cmsUInt32Number Intents[1] = { INTENT_PERCEPTUAL };
    cmsFloat64Number AdaptationStates[1] = { 0.0 };
    cmsHTRANSFORM extTransform = cmsCreateExtendedTransform(NULL, 1, hProfiles, BPC, Intents, AdaptationStates, NULL, 0, TYPE_RGB_8, TYPE_RGB_8, flags);
    if (extTransform) {
        cmsDeleteTransform(extTransform);
    }
    cmsCloseProfile(hProfiles[0]);

    // Test cmsSetProfileVersion
    cmsHPROFILE hProfile = createDummyProfile();
    cmsSetProfileVersion(hProfile, version);
    cmsCloseProfile(hProfile);

    // Test cmsCreateBCHSWabstractProfile
    cmsHPROFILE bchswProfile = cmsCreateBCHSWabstractProfile(256, version, version, version, version, flags, flags);
    if (bchswProfile) {
        cmsCloseProfile(bchswProfile);
    }

    // Test cmsSetAdaptationState
    cmsFloat64Number prevState = cmsSetAdaptationState(version);

    // Test cmsCreateBCHSWabstractProfileTHR
    cmsHPROFILE bchswProfileTHR = cmsCreateBCHSWabstractProfileTHR(NULL, 256, version, version, version, version, flags, flags);
    if (bchswProfileTHR) {
        cmsCloseProfile(bchswProfileTHR);
    }

    return 0;
}