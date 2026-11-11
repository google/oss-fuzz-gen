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
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize TurboJPEG handle for compression
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) {
        return 0;
    }

    // Set various parameters
    tj3Set(handle, TJPARAM_SUBSAMP, TJSAMP_420);
    tj3Set(handle, TJPARAM_QUALITY, 75);
    tj3Set(handle, TJPARAM_NOREALLOC, 1);
    tj3Set(handle, TJPARAM_FASTUPSAMPLE, 1);
    tj3Set(handle, TJPARAM_FASTDCT, 1);
    tj3Set(handle, TJPARAM_PROGRESSIVE, 1);

    // Define image parameters
    int width = 256;
    int height = 256;
    int align = 4;
    int pixelFormat = TJPF_RGB;

    // Calculate buffer sizes
    size_t yuvSize = tj3YUVBufSize(width, align, height, TJSAMP_420);
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of tj3JPEGBufSize
    size_t jpegSize = tj3JPEGBufSize(width, TJ_NUMERR, TJSAMP_420);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Allocate buffers
    unsigned char *yuvBuf = static_cast<unsigned char*>(tj3Alloc(yuvSize));
    unsigned char *jpegBuf = static_cast<unsigned char*>(tj3Alloc(jpegSize));
    if (!yuvBuf || !jpegBuf) {
        tj3Destroy(handle);
        return 0;
    }

    // Check if input data is sufficient for an RGB image
    size_t requiredDataSize = width * height * tjPixelSize[pixelFormat];
    if (Size < requiredDataSize) {
        tj3Free(yuvBuf);
        tj3Free(jpegBuf);
        tj3Destroy(handle);
        return 0;
    }

    // Encode YUV
    if (tj3EncodeYUV8(handle, Data, width, width * tjPixelSize[pixelFormat], height, pixelFormat, yuvBuf, align) == -1) {
        tj3Free(yuvBuf);
        tj3Free(jpegBuf);
        tj3Destroy(handle);
        return 0;
    }

    // Compress from YUV
    unsigned char *jpegBufPtr = jpegBuf;
    size_t jpegBufSize = jpegSize;
    if (tj3CompressFromYUV8(handle, yuvBuf, width, align, height, &jpegBufPtr, &jpegBufSize) == -1) {
        tj3Free(yuvBuf);
        tj3Free(jpegBuf);
        tj3Destroy(handle);
        return 0;
    }

    // Free resources
    tj3Free(yuvBuf);
    tj3Free(jpegBuf);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
