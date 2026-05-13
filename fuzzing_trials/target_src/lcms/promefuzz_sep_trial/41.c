// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// _cmsVEC3distance at cmsmtrx.c:72:28 in lcms2_plugin.h
// _cmsVEC3cross at cmsmtrx.c:50:16 in lcms2_plugin.h
// _cmsMAT3eval at cmsmtrx.c:169:16 in lcms2_plugin.h
// _cmsVEC3dot at cmsmtrx.c:58:28 in lcms2_plugin.h
// _cmsMAT3solve at cmsmtrx.c:156:20 in lcms2_plugin.h
// _cmsVEC3minus at cmsmtrx.c:42:16 in lcms2_plugin.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2_plugin.h>

static cmsVEC3 randomVec3(const uint8_t **data, size_t *size) {
    cmsVEC3 vec;
    if (*size < sizeof(cmsFloat64Number) * 3) {
        memset(&vec, 0, sizeof(cmsVEC3));
        return vec;
    }
    memcpy(&vec, *data, sizeof(cmsVEC3));
    *data += sizeof(cmsVEC3);
    *size -= sizeof(cmsVEC3);
    return vec;
}

static cmsMAT3 randomMat3(const uint8_t **data, size_t *size) {
    cmsMAT3 mat;
    if (*size < sizeof(cmsFloat64Number) * 9) {
        memset(&mat, 0, sizeof(cmsMAT3));
        return mat;
    }
    memcpy(&mat, *data, sizeof(cmsMAT3));
    *data += sizeof(cmsMAT3);
    *size -= sizeof(cmsMAT3);
    return mat;
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz _cmsVEC3distance
    cmsVEC3 vecA = randomVec3(&Data, &Size);
    cmsVEC3 vecB = randomVec3(&Data, &Size);
    cmsFloat64Number distance = _cmsVEC3distance(&vecA, &vecB);

    // Fuzz _cmsVEC3cross
    cmsVEC3 resultCross;
    _cmsVEC3cross(&resultCross, &vecA, &vecB);

    // Fuzz _cmsMAT3eval
    cmsMAT3 matrix = randomMat3(&Data, &Size);
    cmsVEC3 resultEval;
    _cmsMAT3eval(&resultEval, &matrix, &vecA);

    // Fuzz _cmsVEC3dot
    cmsFloat64Number dotProduct = _cmsVEC3dot(&vecA, &vecB);

    // Fuzz _cmsMAT3solve
    cmsVEC3 resultSolve;
    cmsBool solveSuccess = _cmsMAT3solve(&resultSolve, &matrix, &vecB);

    // Fuzz _cmsVEC3minus
    cmsVEC3 resultMinus;
    _cmsVEC3minus(&resultMinus, &vecA, &vecB);

    return 0;
}