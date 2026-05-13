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

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG handle for decompression
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (!handle) return 0;

    // Prepare parameters for tj3DecompressToYUVPlanes8
    unsigned char *jpegBuf = const_cast<unsigned char *>(Data);
    size_t jpegSize = Size;
    unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};

    // Assume some dimensions for fuzzing
    int width = 128, height = 128; 
    int subsamp = TJSAMP_420;

    // Allocate memory for YUV planes
    for (int i = 0; i < 3; i++) {
        int planeSize = tj3YUVPlaneSize(i, width, strides[i], height, subsamp);
        dstPlanes[i] = static_cast<unsigned char *>(malloc(planeSize));
        if (!dstPlanes[i]) {
            tj3Destroy(handle);
            return 0;
        }
    }

    // Call tj3DecompressToYUVPlanes8
    tj3DecompressToYUVPlanes8(handle, jpegBuf, jpegSize, dstPlanes, strides);

    // Clean up
    for (int i = 0; i < 3; i++) {
        free(dstPlanes[i]);
    }

    // Initialize TurboJPEG handle for compression
    tjhandle cHandle = tj3Init(TJINIT_COMPRESS);
    if (!cHandle) {
        tj3Destroy(handle);
        return 0;
    }

    // Prepare parameters for tj3CompressFromYUVPlanes8
    unsigned char *jpegBufOut = nullptr;
    size_t jpegSizeOut = 0;

    // Call tj3CompressFromYUVPlanes8
    tj3CompressFromYUVPlanes8(cHandle, const_cast<const unsigned char **>(dstPlanes), width, strides, height, &jpegBufOut, &jpegSizeOut);

    // Clean up
    if (jpegBufOut) tj3Free(jpegBufOut);
    tj3Destroy(cHandle);
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
