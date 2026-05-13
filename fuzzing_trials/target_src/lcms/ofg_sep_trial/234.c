#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

typedef cmsBool (*cmsSAMPLERFLOAT)(const cmsFloat32Number[], cmsFloat32Number[], void *);

cmsBool sampleFunction(const cmsFloat32Number in[], cmsFloat32Number out[], void *cargo) {
    // Simple example sampler that copies input to output
    for (int i = 0; i < 3; i++) {
        out[i] = in[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_234(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    cmsUInt32Number nPoints = *(const cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    if (size < nPoints * sizeof(cmsUInt32Number)) {
        return 0;
    }

    const cmsUInt32Number *range = (const cmsUInt32Number *)data;
    data += nPoints * sizeof(cmsUInt32Number);
    size -= nPoints * sizeof(cmsUInt32Number);

    void *cargo = (void *)data;

    cmsSliceSpaceFloat(nPoints, range, sampleFunction, cargo);

    return 0;
}