// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildGamma at cmsgamma.c:909:25 in lcms2.h
// cmsStageAllocToneCurves at cmslut.c:248:21 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsCreateContext at cmsplugin.c:824:22 in lcms2.h
// cmsStageOutputChannels at cmslut.c:1223:28 in lcms2.h
// cmsStageInputChannels at cmslut.c:1218:28 in lcms2.h
// cmsStageAllocCLutFloatGranular at cmslut.c:642:21 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageAllocCLut16bit at cmslut.c:607:21 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsDeleteContext at cmsplugin.c:963:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static cmsStage* createDummyStage(cmsContext context, cmsUInt32Number inputChan, cmsUInt32Number outputChan) {
    if (inputChan > 3) return NULL; // Ensure we do not exceed the array size

    cmsToneCurve* curve = cmsBuildGamma(context, 2.2);
    cmsToneCurve* curves[3] = { curve, curve, curve };
    cmsStage* stage = cmsStageAllocToneCurves(context, inputChan, curves);
    cmsFreeToneCurve(curve);
    return stage;
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 3) return 0;

    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number inputChan = *(cmsUInt32Number*)Data;
    cmsUInt32Number outputChan = *(cmsUInt32Number*)(Data + sizeof(cmsUInt32Number));
    cmsUInt32Number nGridPoints = *(cmsUInt32Number*)(Data + 2 * sizeof(cmsUInt32Number));

    cmsStage* stage = createDummyStage(context, inputChan, outputChan);
    if (stage) {
        cmsUInt32Number outChans = cmsStageOutputChannels(stage);
        cmsUInt32Number inChans = cmsStageInputChannels(stage);

        cmsUInt32Number clutPoints[3] = { nGridPoints, nGridPoints, nGridPoints };
        cmsFloat32Number* floatTable = (cmsFloat32Number*)malloc(sizeof(cmsFloat32Number) * nGridPoints * inputChan * outputChan);
        if (floatTable) {
            memset(floatTable, 0, sizeof(cmsFloat32Number) * nGridPoints * inputChan * outputChan);
            cmsStage* clutStage = cmsStageAllocCLutFloatGranular(context, clutPoints, inputChan, outputChan, floatTable);
            if (clutStage) {
                cmsStageFree(clutStage);
            }
            free(floatTable);
        }

        cmsUInt16Number* table16 = (cmsUInt16Number*)malloc(sizeof(cmsUInt16Number) * nGridPoints * inputChan * outputChan);
        if (table16) {
            memset(table16, 0, sizeof(cmsUInt16Number) * nGridPoints * inputChan * outputChan);
            cmsStage* clut16Stage = cmsStageAllocCLut16bit(context, nGridPoints, inputChan, outputChan, table16);
            if (clut16Stage) {
                cmsStageFree(clut16Stage);
            }
            free(table16);
        }

        cmsStageFree(stage);
    }

    cmsDeleteContext(context);
    return 0;
}