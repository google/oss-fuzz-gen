// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsStageAllocCLutFloatGranular at cmslut.c:642:21 in lcms2.h
// cmsStageSampleCLutFloat at cmslut.c:813:19 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageAllocCLut16bitGranular at cmslut.c:547:21 in lcms2.h
// cmsStageSampleCLut16bit at cmslut.c:747:19 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageAllocCLutFloat at cmslut.c:624:21 in lcms2.h
// cmsStageSampleCLutFloat at cmslut.c:813:19 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsSliceSpaceFloat at cmslut.c:910:26 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

// Dummy sampler function for cmsStageSampleCLutFloat and cmsSliceSpaceFloat
static cmsBool SampleFloat(cmsFloat32Number* In, cmsFloat32Number* Out, void* Cargo) {
    return TRUE;
}

// Dummy sampler function for cmsStageSampleCLut16bit
static cmsBool Sample16bit(cmsUInt16Number* In, cmsUInt16Number* Out, void* Cargo) {
    return TRUE;
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cmsUInt32Number) * 3) return 0;

    cmsContext context = NULL;
    cmsUInt32Number clutPoints[3] = {0};
    cmsUInt32Number inputChan, outputChan;
    cmsFloat32Number* floatTable = NULL;
    cmsUInt16Number* int16Table = NULL;
    cmsStage* stage = NULL;

    // Extract values from the input data
    clutPoints[0] = Data[0] % 10 + 2; // Ensure at least 2 points
    clutPoints[1] = Data[1] % 10 + 2; // Ensure at least 2 points
    clutPoints[2] = Data[2] % 10 + 2; // Ensure at least 2 points
    inputChan = Data[3] % 3 + 1;      // Ensure at least 1 channel
    outputChan = Data[4] % 3 + 1;     // Ensure at least 1 channel

    // Calculate the total number of entries in the CLUT for cmsStageAllocCLutFloat
    cmsUInt32Number totalEntriesFloat = 1;
    for (size_t i = 0; i < inputChan; i++) {
        totalEntriesFloat *= clutPoints[0]; // Use clutPoints[0] for consistency with cmsStageAllocCLutFloat
    }
    totalEntriesFloat *= outputChan;

    // Calculate the total number of entries in the CLUT for cmsStageAllocCLutFloatGranular and cmsStageAllocCLut16bitGranular
    cmsUInt32Number totalEntriesGranular = 1;
    for (size_t i = 0; i < inputChan; i++) {
        totalEntriesGranular *= clutPoints[i % 3]; // Use modulo to avoid out of bounds
    }
    totalEntriesGranular *= outputChan;

    // Allocate dummy tables with the correct size
    floatTable = (cmsFloat32Number*) malloc(sizeof(cmsFloat32Number) * totalEntriesGranular);
    int16Table = (cmsUInt16Number*) malloc(sizeof(cmsUInt16Number) * totalEntriesGranular);

    if (!floatTable || !int16Table) {
        free(floatTable);
        free(int16Table);
        return 0;
    }

    // Test cmsStageAllocCLutFloatGranular
    stage = cmsStageAllocCLutFloatGranular(context, clutPoints, inputChan, outputChan, floatTable);
    if (stage) {
        cmsStageSampleCLutFloat(stage, SampleFloat, NULL, 0);
        cmsStageFree(stage);
    }

    // Test cmsStageAllocCLut16bitGranular
    stage = cmsStageAllocCLut16bitGranular(context, clutPoints, inputChan, outputChan, int16Table);
    if (stage) {
        cmsStageSampleCLut16bit(stage, Sample16bit, NULL, 0);
        cmsStageFree(stage);
    }

    // Allocate a separate table for cmsStageAllocCLutFloat
    cmsFloat32Number* floatTableForFloat = (cmsFloat32Number*) malloc(sizeof(cmsFloat32Number) * totalEntriesFloat);
    if (floatTableForFloat) {
        // Test cmsStageAllocCLutFloat
        stage = cmsStageAllocCLutFloat(context, clutPoints[0], inputChan, outputChan, floatTableForFloat);
        if (stage) {
            cmsStageSampleCLutFloat(stage, SampleFloat, NULL, 0);
            cmsStageFree(stage);
        }
        free(floatTableForFloat);
    }

    // Test cmsSliceSpaceFloat
    cmsSliceSpaceFloat(inputChan, clutPoints, SampleFloat, NULL);

    // Clean up
    free(floatTable);
    free(int16Table);

    return 0;
}