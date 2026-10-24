#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../src/turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int initType = *reinterpret_cast<const int*>(Data);
    Data += sizeof(int);
    Size -= sizeof(int);

    // Initialize TurboJPEG instance
    tjhandle handle = tj3Init(initType);
    if (!handle) {
        return 0;
    }

    // Test tj3SetCroppingRegion
    if (Size >= sizeof(tjregion)) {
        tjregion croppingRegion;
        memcpy(&croppingRegion, Data, sizeof(tjregion));
        tj3SetCroppingRegion(handle, croppingRegion);
        Data += sizeof(tjregion);
        Size -= sizeof(tjregion);
    }

    // Test tj3GetScalingFactors
    int numScalingFactors = 0;
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(&numScalingFactors);

    // Test tj3SetScalingFactor
    if (scalingFactors && numScalingFactors > 0) {
        tj3SetScalingFactor(handle, scalingFactors[0]);
    }

    // Test tjGetScalingFactors
    int numScalingFactorsLegacy = 0;
    tjscalingfactor *scalingFactorsLegacy = tjGetScalingFactors(&numScalingFactorsLegacy);

    // Prepare dummy JPEG data for tjDecompressToYUVPlanes
    if (Size > 0) {
        unsigned long jpegSize = static_cast<unsigned long>(Size);
        unsigned char *jpegBuf = const_cast<unsigned char*>(Data);

        int width = 100, height = 100;
        unsigned char *dstPlanes[3];
        int strides[3] = { width, width / 2, width / 2 };

        for (int i = 0; i < 3; i++) {
            dstPlanes[i] = static_cast<unsigned char*>(malloc(width * height));
        }

        tjDecompressToYUVPlanes(handle, jpegBuf, jpegSize, dstPlanes, width, strides, height, 0);

        for (int i = 0; i < 3; i++) {
            free(dstPlanes[i]);
        }
    }

    tj3Destroy(handle);
    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
