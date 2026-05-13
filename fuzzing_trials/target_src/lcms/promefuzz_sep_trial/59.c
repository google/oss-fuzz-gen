// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsDoTransformLineStride at cmsxform.c:229:16 in lcms2.h
// cmsCreateTransform at cmsxform.c:1355:32 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCreateMultiprofileTransform at cmsxform.c:1316:25 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsGetTransformInputFormat at cmsxform.c:1429:27 in lcms2.h
// cmsCreateTransform at cmsxform.c:1355:32 in lcms2.h
// cmsDeleteTransform at cmsxform.c:147:16 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsDoTransform at cmsxform.c:192:16 in lcms2.h
// cmsDoTransformStride at cmsxform.c:211:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static cmsHPROFILE createDummyProfile() {
    // Create a dummy profile for testing
    cmsHPROFILE profile = cmsCreate_sRGBProfile();
    return profile;
}

static void testCreateMultiprofileTransform(const uint8_t *Data, size_t Size) {
    if (Size < 6 * sizeof(cmsUInt32Number)) return;

    cmsHPROFILE profiles[2];
    profiles[0] = createDummyProfile();
    profiles[1] = createDummyProfile();

    cmsUInt32Number nProfiles = (Data[0] % 256) + 1;
    cmsUInt32Number inputFormat = *(cmsUInt32Number *)(Data + 1);
    cmsUInt32Number outputFormat = *(cmsUInt32Number *)(Data + 2);
    cmsUInt32Number intent = *(cmsUInt32Number *)(Data + 3);
    cmsUInt32Number flags = *(cmsUInt32Number *)(Data + 4);

    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, nProfiles, inputFormat, outputFormat, intent, flags);
    if (transform) {
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(profiles[0]);
    cmsCloseProfile(profiles[1]);
}

static void testGetTransformInputFormat(cmsHTRANSFORM transform) {
    cmsUInt32Number format = cmsGetTransformInputFormat(transform);
    (void)format; // Use the format or add checks
}

static void testCreateTransform(const uint8_t *Data, size_t Size) {
    if (Size < 5 * sizeof(cmsUInt32Number)) return;

    cmsHPROFILE inputProfile = createDummyProfile();
    cmsHPROFILE outputProfile = createDummyProfile();

    cmsUInt32Number inputFormat = *(cmsUInt32Number *)(Data + 0);
    cmsUInt32Number outputFormat = *(cmsUInt32Number *)(Data + 1);
    cmsUInt32Number intent = *(cmsUInt32Number *)(Data + 2);
    cmsUInt32Number flags = *(cmsUInt32Number *)(Data + 3);

    cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);
    if (transform) {
        testGetTransformInputFormat(transform);
        cmsDeleteTransform(transform);
    }

    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
}

static void testDoTransform(cmsHTRANSFORM transform, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    void *outputBuffer = malloc(Size);
    if (!outputBuffer) return;

    cmsDoTransform(transform, Data, outputBuffer, (cmsUInt32Number)Size);
    free(outputBuffer);
}

static void testDoTransformStride(cmsHTRANSFORM transform, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number)) return;

    cmsUInt32Number stride = *(cmsUInt32Number *)(Data + 0);
    void *outputBuffer = malloc(Size);
    if (!outputBuffer) return;

    cmsDoTransformStride(transform, Data, outputBuffer, (cmsUInt32Number)Size, stride);
    free(outputBuffer);
}

static void testDoTransformLineStride(cmsHTRANSFORM transform, const uint8_t *Data, size_t Size) {
    if (Size < 4 * sizeof(cmsUInt32Number)) return;

    cmsUInt32Number pixelsPerLine = *(cmsUInt32Number *)(Data + 0);
    cmsUInt32Number lineCount = *(cmsUInt32Number *)(Data + 1);
    cmsUInt32Number bytesPerLineIn = *(cmsUInt32Number *)(Data + 2);
    cmsUInt32Number bytesPerLineOut = *(cmsUInt32Number *)(Data + 3);
    cmsUInt32Number bytesPerPlaneIn = *(cmsUInt32Number *)(Data + 4);
    cmsUInt32Number bytesPerPlaneOut = *(cmsUInt32Number *)(Data + 5);

    void *outputBuffer = malloc(Size);
    if (!outputBuffer) return;

    cmsDoTransformLineStride(transform, Data, outputBuffer, pixelsPerLine, lineCount, bytesPerLineIn, bytesPerLineOut, bytesPerPlaneIn, bytesPerPlaneOut);
    free(outputBuffer);
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    testCreateMultiprofileTransform(Data, Size);
    testCreateTransform(Data, Size);

    cmsHPROFILE inputProfile = createDummyProfile();
    cmsHPROFILE outputProfile = createDummyProfile();

    if (Size >= 5 * sizeof(cmsUInt32Number)) {
        cmsUInt32Number inputFormat = *(cmsUInt32Number *)(Data + 0);
        cmsUInt32Number outputFormat = *(cmsUInt32Number *)(Data + 1);
        cmsUInt32Number intent = *(cmsUInt32Number *)(Data + 2);
        cmsUInt32Number flags = *(cmsUInt32Number *)(Data + 3);

        cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);
        if (transform) {
            testDoTransform(transform, Data, Size);
            testDoTransformStride(transform, Data, Size);
            testDoTransformLineStride(transform, Data, Size);
            cmsDeleteTransform(transform);
        }
    }

    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

    return 0;
}