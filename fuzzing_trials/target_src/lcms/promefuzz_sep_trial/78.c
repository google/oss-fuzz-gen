// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsBuildTabulatedToneCurve16 at cmsgamma.c:783:25 in lcms2.h
// cmsStageAllocMatrix at cmslut.c:379:22 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageAllocToneCurves at cmslut.c:248:21 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsFreeToneCurve at cmsgamma.c:916:16 in lcms2.h
// cmsStageAllocCLutFloat at cmslut.c:624:21 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
// cmsStageAllocIdentity at cmslut.c:70:21 in lcms2.h
// cmsStageOutputChannels at cmslut.c:1223:28 in lcms2.h
// cmsStageInputChannels at cmslut.c:1218:28 in lcms2.h
// cmsStageFree at cmslut.c:1209:16 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

static cmsFloat64Number* generateRandomMatrix(size_t rows, size_t cols, const uint8_t* data, size_t dataSize, size_t* offset) {
    cmsFloat64Number* matrix = (cmsFloat64Number*)malloc(rows * cols * sizeof(cmsFloat64Number));
    if (!matrix) return NULL;
    for (size_t i = 0; i < rows * cols; i++) {
        if (*offset >= dataSize) *offset = 0;
        matrix[i] = (cmsFloat64Number)data[(*offset)++] / 255.0;
    }
    return matrix;
}

static cmsFloat32Number* generateRandomTable(size_t size, const uint8_t* data, size_t dataSize, size_t* offset) {
    cmsFloat32Number* table = (cmsFloat32Number*)malloc(size * sizeof(cmsFloat32Number));
    if (!table) return NULL;
    for (size_t i = 0; i < size; i++) {
        if (*offset >= dataSize) *offset = 0;
        table[i] = (cmsFloat32Number)data[(*offset)++] / 255.0f;
    }
    return table;
}

static cmsToneCurve* generateRandomToneCurve(const uint8_t* data, size_t dataSize, size_t* offset) {
    if (*offset >= dataSize) *offset = 0;
    cmsUInt16Number nEntries = data[(*offset)++];
    cmsUInt16Number* table16 = (cmsUInt16Number*)malloc(nEntries * sizeof(cmsUInt16Number));
    if (!table16) return NULL;
    for (size_t i = 0; i < nEntries; i++) {
        if (*offset >= dataSize) *offset = 0;
        table16[i] = (cmsUInt16Number)data[(*offset)++];
    }
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(NULL, nEntries, table16);
    free(table16);
    return curve;
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    size_t offset = 0;
    cmsContext context = NULL;

    // Test cmsStageAllocMatrix
    cmsUInt32Number rows = Data[offset++ % Size] + 1;  // Ensure at least 1 row
    cmsUInt32Number cols = Data[offset++ % Size] + 1;  // Ensure at least 1 column
    cmsFloat64Number* matrix = generateRandomMatrix(rows, cols, Data, Size, &offset);
    cmsFloat64Number* offsetMatrix = generateRandomMatrix(rows, 1, Data, Size, &offset);
    cmsStage* stageMatrix = cmsStageAllocMatrix(context, rows, cols, matrix, offsetMatrix);
    if (stageMatrix) {
        cmsStageFree(stageMatrix);
    }
    free(matrix);
    free(offsetMatrix);

    // Test cmsStageAllocToneCurves
    cmsUInt32Number nChannels = Data[offset++ % Size] % 10 + 1;  // Ensure at least 1 channel and max 10
    cmsToneCurve* curves[10];
    for (cmsUInt32Number i = 0; i < nChannels; i++) {
        curves[i] = generateRandomToneCurve(Data, Size, &offset);
    }
    cmsStage* stageToneCurves = cmsStageAllocToneCurves(context, nChannels, curves);
    if (stageToneCurves) {
        cmsStageFree(stageToneCurves);
    }
    for (cmsUInt32Number i = 0; i < nChannels; i++) {
        if (curves[i]) {
            cmsFreeToneCurve(curves[i]);
        }
    }

    // Test cmsStageAllocCLutFloat
    cmsUInt32Number nGridPoints = Data[offset++ % Size] + 1;  // Ensure at least 1 grid point
    cmsUInt32Number inputChan = Data[offset++ % Size] + 1;    // Ensure at least 1 input channel
    cmsUInt32Number outputChan = Data[offset++ % Size] + 1;   // Ensure at least 1 output channel
    size_t tableSize = nGridPoints * inputChan * outputChan;
    cmsFloat32Number* table = generateRandomTable(tableSize, Data, Size, &offset);
    cmsStage* stageCLutFloat = cmsStageAllocCLutFloat(context, nGridPoints, inputChan, outputChan, table);
    if (stageCLutFloat) {
        cmsStageFree(stageCLutFloat);
    }
    free(table);

    // Test cmsStageAllocIdentity
    cmsUInt32Number identityChannels = Data[offset++ % Size] + 1;  // Ensure at least 1 channel
    cmsStage* stageIdentity = cmsStageAllocIdentity(context, identityChannels);
    if (stageIdentity) {
        // Test cmsStageOutputChannels and cmsStageInputChannels
        cmsUInt32Number outputChannels = cmsStageOutputChannels(stageIdentity);
        cmsUInt32Number inputChannels = cmsStageInputChannels(stageIdentity);
        cmsStageFree(stageIdentity);
    }

    return 0;
}