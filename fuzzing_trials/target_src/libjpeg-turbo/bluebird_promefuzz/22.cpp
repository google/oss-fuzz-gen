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
#include <cstring>
#include <cstdio>

static tjhandle createDecompressor() {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        fprintf(stderr, "Failed to create decompressor: %s\n", tjGetErrorStr());
    }
    return handle;
}

static tjhandle createCompressor() {
    tjhandle handle = tjInitCompress();
    if (!handle) {
        fprintf(stderr, "Failed to create compressor: %s\n", tjGetErrorStr());
    }
    return handle;
}

static void destroyHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG handles
    tjhandle compressor = createCompressor();
    tjhandle decompressor = createDecompressor();
    if (!compressor || !decompressor) {
        destroyHandle(compressor);
        destroyHandle(decompressor);
        return 0;
    }

    // Simulate a basic setup for tjCompress
    int width = 256, height = 256, pixelSize = 3;
    unsigned long compressedSize = 0;
    unsigned char *compressedBuf = nullptr;
    unsigned char *srcBuf = (unsigned char *)malloc(width * height * pixelSize);
    if (!srcBuf) {
        destroyHandle(compressor);
        destroyHandle(decompressor);
        return 0;
    }
    memcpy(srcBuf, Data, Size < width * height * pixelSize ? Size : width * height * pixelSize);

    // Fuzz tjCompress
    tjCompress(compressor, srcBuf, width, 0, height, pixelSize, compressedBuf, &compressedSize, TJSAMP_444, 100, TJFLAG_FASTDCT);

    // Fuzz tj3EncodeYUVPlanes8
    unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {width, width / 2, width / 2};
    tj3EncodeYUVPlanes8(compressor, srcBuf, width, 0, height, TJPF_RGB, dstPlanes, strides);

    // Fuzz tj3GetErrorCode
    int errorCode = tj3GetErrorCode(compressor);

    // Fuzz tjCompressFromYUVPlanes
    const unsigned char *srcPlanes[3] = {srcBuf, srcBuf + width * height, srcBuf + width * height * 2};
    tjCompressFromYUVPlanes(compressor, srcPlanes, width, strides, height, TJSAMP_444, &compressedBuf, &compressedSize, 100, TJFLAG_FASTDCT);

    // Free the compressed buffer after use
    tjFree(compressedBuf);

    // Fuzz tjDecodeYUVPlanes
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * pixelSize);
    if (dstBuf) {
        tjDecodeYUVPlanes(decompressor, srcPlanes, strides, TJSAMP_444, dstBuf, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);
        free(dstBuf);
    }

    // Fuzz tjGetErrorCode
    errorCode = tjGetErrorCode(decompressor);

    // Clean up
    free(srcBuf);
    destroyHandle(compressor);
    destroyHandle(decompressor);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
