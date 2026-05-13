// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsCreateBCHSWabstractProfile at cmsvirt.c:946:32 in lcms2.h
// cmsCreateExtendedTransform at cmsxform.c:1123:25 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsTransform2DeviceLink at cmsvirt.c:1194:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsSetProfileVersion at cmsio0.c:1139:17 in lcms2.h
// cmsSetAdaptationState at cmsxform.c:77:28 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
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
    return cmsCreateBCHSWabstractProfile(33, 1.0, 1.0, 1.0, 1.0, 6500, 6500);
}

static cmsHTRANSFORM createDummyTransform(cmsContext ContextID, cmsHPROFILE hProfile) {
    cmsHPROFILE profiles[1] = {hProfile};
    cmsUInt32Number intents[1] = {INTENT_PERCEPTUAL};
    cmsBool BPC[1] = {FALSE};
    cmsFloat64Number adaptationStates[1] = {1.0};

    return cmsCreateExtendedTransform(ContextID, 1, profiles, BPC, intents, adaptationStates, NULL, 0, TYPE_RGB_8, TYPE_RGB_8, 0);
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    cmsContext ContextID = NULL;
    cmsHPROFILE hProfile = createDummyProfile();
    if (!hProfile) {
        return 0;
    }

    cmsHTRANSFORM hTransform = createDummyTransform(ContextID, hProfile);
    if (!hTransform) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    cmsFloat64Number version = *((cmsFloat64Number*)Data);
    cmsUInt32Number flags = *((cmsUInt32Number*)(Data + sizeof(cmsFloat64Number)));

    cmsHPROFILE deviceLinkProfile = cmsTransform2DeviceLink(hTransform, version, flags);
    if (deviceLinkProfile) {
        cmsCloseProfile(deviceLinkProfile);
    }

    cmsSetProfileVersion(hProfile, version);

    cmsSetAdaptationState(version);

    cmsCloseProfile(hProfile);
    cmsDeleteTransform(hTransform);

    cmsHPROFILE abstractProfileTHR = cmsCreateBCHSWabstractProfileTHR(ContextID, 33, 1.0, 1.0, 1.0, 1.0, 6500, 6500);
    if (abstractProfileTHR) {
        cmsCloseProfile(abstractProfileTHR);
    }

    return 0;
}