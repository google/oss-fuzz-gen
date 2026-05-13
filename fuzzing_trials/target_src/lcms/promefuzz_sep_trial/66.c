// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsCreateLinearizationDeviceLink at cmsvirt.c:340:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateInkLimitingDeviceLink at cmsvirt.c:466:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateInkLimitingDeviceLinkTHR at cmsvirt.c:393:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsChannelsOfColorSpace at cmspcs.c:877:26 in lcms2.h
// cmsCreateBCHSWabstractProfile at cmsvirt.c:946:32 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreateLinearizationDeviceLinkTHR at cmsvirt.c:288:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

static cmsToneCurve* createToneCurve(void) {
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 1.0);
    return toneCurve;
}

static void freeToneCurve(cmsToneCurve* toneCurve) {
    if (toneCurve) {
        cmsFreeToneCurve(toneCurve);
    }
}

int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number)) return 0;

    cmsColorSpaceSignature colorSpace = *(cmsColorSpaceSignature*)Data;
    cmsFloat64Number limit = *(cmsFloat64Number*)(Data + sizeof(cmsUInt32Number));

    cmsToneCurve* toneCurve = createToneCurve();
    if (!toneCurve) return 0;

    cmsToneCurve* toneCurves[] = { toneCurve, toneCurve, toneCurve, toneCurve };
    cmsContext context = NULL;

    cmsHPROFILE profile1 = cmsCreateLinearizationDeviceLink(colorSpace, toneCurves);
    if (profile1) cmsCloseProfile(profile1);

    cmsHPROFILE profile2 = cmsCreateInkLimitingDeviceLink(colorSpace, limit);
    if (profile2) cmsCloseProfile(profile2);

    cmsHPROFILE profile3 = cmsCreateInkLimitingDeviceLinkTHR(context, colorSpace, limit);
    if (profile3) cmsCloseProfile(profile3);

    cmsInt32Number channels = cmsChannelsOfColorSpace(colorSpace);

    cmsHPROFILE profile4 = cmsCreateBCHSWabstractProfile(33, 1.0, 1.0, 1.0, 1.0, 6500, 5000);
    if (profile4) cmsCloseProfile(profile4);

    cmsHPROFILE profile5 = cmsCreateLinearizationDeviceLinkTHR(context, colorSpace, toneCurves);
    if (profile5) cmsCloseProfile(profile5);

    freeToneCurve(toneCurve);

    return 0;
}