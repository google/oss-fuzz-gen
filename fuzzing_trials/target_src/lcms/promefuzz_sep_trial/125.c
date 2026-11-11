// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsCreateContext at cmsplugin.c:824:22 in lcms2.h
// cmsStageAllocMatrix at cmslut.c:379:22 in lcms2.h
// cmsGetStageContextID at cmslut.c:1238:22 in lcms2.h
// cmsStageNext at cmslut.c:1243:22 in lcms2.h
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsStageAllocToneCurves at cmslut.c:248:21 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsStageAllocIdentity at cmslut.c:70:21 in lcms2.h
// _cmsStageAllocPlaceholder at cmslut.c:31:21 in lcms2_plugin.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <lcms2_plugin.h>

static cmsFloat64Number dummyEvalFn(cmsInt32Number Type, const cmsFloat64Number Params[10], cmsFloat64Number R) {
    return R; // Dummy evaluator function
}

static void cleanupStage(cmsStage* stage) {
    if (stage) {
        cmsStageFree(stage);
    }
}

int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsFloat64Number) * 12) return 0;

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) return 0;

    cmsUInt32Number rows = 3;
    cmsUInt32Number cols = 3;
    cmsFloat64Number matrix[9];
    cmsFloat64Number offset[3];

    memcpy(matrix, Data, sizeof(matrix));
    memcpy(offset, Data + sizeof(matrix), sizeof(offset));

    cmsStage* matrixStage = cmsStageAllocMatrix(context, rows, cols, matrix, offset);
    if (matrixStage) {
        cmsContext ctxID = cmsGetStageContextID(matrixStage);
        (void)ctxID; // Use the context ID

        cmsStage* nextStage = cmsStageNext(matrixStage);
        (void)nextStage; // Use the next stage

        cleanupStage(matrixStage);
    }

    cmsUInt32Number nChannels = 3;
    cmsToneCurve* curves[3];
    for (int i = 0; i < 3; i++) {
        curves[i] = cmsBuildGamma(context, 2.2);
    }
    cmsStage* toneCurveStage = cmsStageAllocToneCurves(context, nChannels, curves);
    if (toneCurveStage) {
        cleanupStage(toneCurveStage);
    }
    for (int i = 0; i < 3; i++) {
        cmsFreeToneCurve(curves[i]);
    }

    cmsStage* identityStage = cmsStageAllocIdentity(context, nChannels);
    if (identityStage) {
        cleanupStage(identityStage);
    }

    cmsStage* placeholderStage = _cmsStageAllocPlaceholder(
        context,
        cmsSigMatrixElemType,
        nChannels,
        nChannels,
        (void*)dummyEvalFn,
        NULL,
        NULL,
        NULL
    );
    if (placeholderStage) {
        cleanupStage(placeholderStage);
    }

    cmsDeleteContext(context);
    return 0;
}