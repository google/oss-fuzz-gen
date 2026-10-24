// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsDetectTAC at cmsgmt.c:462:28 in lcms2.h
// cmsDetectRGBProfileGamma at cmsgmt.c:605:28 in lcms2.h
// cmsGetHeaderCreator at cmsio0.c:1021:27 in lcms2.h
// cmsGetProfileVersion at cmsio0.c:1148:28 in lcms2.h
// cmsGetPostScriptCRD at cmsps2.c:1552:27 in lcms2.h
// cmsSetProfileVersion at cmsio0.c:1139:17 in lcms2.h
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

static cmsHPROFILE createDummyProfile(const uint8_t *Data, size_t Size) {
    char filename[] = "./dummy_file";
    FILE *file = fopen(filename, "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);
    return cmsOpenProfileFromFile(filename, "r");
}

static void fuzz_cmsDetectTAC(cmsHPROFILE hProfile) {
    cmsFloat64Number result = cmsDetectTAC(hProfile);
    (void)result;
}

static void fuzz_cmsDetectRGBProfileGamma(cmsHPROFILE hProfile) {
    cmsFloat64Number threshold = 0.1;  // Arbitrary threshold
    cmsFloat64Number gamma = cmsDetectRGBProfileGamma(hProfile, threshold);
    (void)gamma;
}

static void fuzz_cmsGetHeaderCreator(cmsHPROFILE hProfile) {
    cmsUInt32Number creator = cmsGetHeaderCreator(hProfile);
    (void)creator;
}

static void fuzz_cmsGetProfileVersion(cmsHPROFILE hProfile) {
    cmsFloat64Number version = cmsGetProfileVersion(hProfile);
    (void)version;
}

static void fuzz_cmsGetPostScriptCRD(cmsHPROFILE hProfile) {
    cmsContext context = NULL;  // Use default context
    cmsUInt32Number intent = 0; // Arbitrary intent
    cmsUInt32Number flags = 0;  // No flags
    char buffer[1024];
    cmsUInt32Number bytesWritten = cmsGetPostScriptCRD(context, hProfile, intent, flags, buffer, sizeof(buffer));
    (void)bytesWritten;
}

static void fuzz_cmsSetProfileVersion(cmsHPROFILE hProfile) {
    cmsFloat64Number version = 4.3; // Arbitrary version number
    cmsSetProfileVersion(hProfile, version);
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cmsHPROFILE hProfile = createDummyProfile(Data, Size);
    if (!hProfile) return 0;

    fuzz_cmsDetectTAC(hProfile);
    fuzz_cmsDetectRGBProfileGamma(hProfile);
    fuzz_cmsGetHeaderCreator(hProfile);
    fuzz_cmsGetProfileVersion(hProfile);
    fuzz_cmsGetPostScriptCRD(hProfile);
    fuzz_cmsSetProfileVersion(hProfile);

    cmsCloseProfile(hProfile);
    return 0;
}