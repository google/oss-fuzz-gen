// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsStageAllocCLutFloatGranular at cmslut.c:642:21 in lcms2.h
// cmsStageAllocCLut16bitGranular at cmslut.c:547:21 in lcms2.h
// cmsStageSampleCLutFloat at cmslut.c:813:19 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageSampleCLut16bit at cmslut.c:747:19 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsSliceSpaceFloat at cmslut.c:910:26 in lcms2.h
// cmsSliceSpace16 at cmslut.c:879:19 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

#define MAX_CLUT_POINTS 16
#define MAX_CHANNELS 16

static cmsBool SampleCLutFloat(cmsFloat32Number In[], cmsFloat32Number Out[], void* Cargo) {
    // Ensure non-null pointers
    if (!In || !Out) return FALSE;

    // Simple sampler that just copies input to output
    for (int i = 0; i < MAX_CHANNELS; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

static cmsBool SampleCLut16(cmsUInt16Number In[], cmsUInt16Number Out[], void* Cargo) {
    // Ensure non-null pointers
    if (!In || !Out) return FALSE;

    // Simple sampler that just copies input to output
    for (int i = 0; i < MAX_CHANNELS; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 2) return 0;

    cmsContext context = NULL;
    cmsUInt32Number clutPoints[MAX_CLUT_POINTS];
    cmsUInt32Number inputChan = Data[0] % MAX_CHANNELS + 1;  // Ensure at least 1 channel
    cmsUInt32Number outputChan = Data[1] % MAX_CHANNELS + 1; // Ensure at least 1 channel

    // Fill clutPoints with some data
    for (int i = 0; i < MAX_CLUT_POINTS; i++) {
        clutPoints[i] = Data[i % Size];
    }

    // Calculate the total number of elements needed for the tables
    size_t totalElements = 1;
    for (int i = 0; i < inputChan; i++) {
        totalElements *= clutPoints[i];
    }
    totalElements *= outputChan;

    cmsFloat32Number* floatTable = (cmsFloat32Number*)malloc(totalElements * sizeof(cmsFloat32Number));
    cmsUInt16Number* intTable = (cmsUInt16Number*)malloc(totalElements * sizeof(cmsUInt16Number));

    if (!floatTable || !intTable) {
        free(floatTable);
        free(intTable);
        return 0;
    }

    // Fill tables with some data
    for (size_t i = 0; i < totalElements; i++) {
        floatTable[i] = (cmsFloat32Number)Data[i % Size] / 255.0f;
        intTable[i] = (cmsUInt16Number)Data[i % Size];
    }

    // Allocate CLUT stages
    cmsStage* stageFloat = cmsStageAllocCLutFloatGranular(context, clutPoints, inputChan, outputChan, floatTable);
    cmsStage* stageInt = cmsStageAllocCLut16bitGranular(context, clutPoints, inputChan, outputChan, intTable);

    // Sample CLUT stages
    if (stageFloat) {
        cmsStageSampleCLutFloat(stageFloat, SampleCLutFloat, NULL, 0);
        cmsStageFree(stageFloat);
    }

    if (stageInt) {
        cmsStageSampleCLut16bit(stageInt, SampleCLut16, NULL, 0);
        cmsStageFree(stageInt);
    }

    // Slice space functions
    cmsSliceSpaceFloat(inputChan, clutPoints, SampleCLutFloat, NULL);
    cmsSliceSpace16(inputChan, clutPoints, SampleCLut16, NULL);

    free(floatTable);
    free(intTable);

    return 0;
}