// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// tjDecodeYUV at turbojpeg.c:2724:15 in turbojpeg.h
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <turbojpeg.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

static void fuzz_tjBufSizeYUV(int width, int height, int subsamp) {
    unsigned long size = tjBufSizeYUV(width, height, subsamp);
    (void)size;  // Suppress unused variable warning
}

static void fuzz_tjDecompressHeader2(tjhandle handle, unsigned char *jpegBuf, unsigned long jpegSize) {
    int width, height, jpegSubsamp;
    int result = tjDecompressHeader2(handle, jpegBuf, jpegSize, &width, &height, &jpegSubsamp);
    if (result == 0) {
        // Successfully decompressed header
    }
}

static void fuzz_tjCompress(tjhandle handle, unsigned char *srcBuf, int width, int height, int pixelSize) {
    unsigned long compressedSize = tjBufSizeYUV(width, height, TJSAMP_444);
    unsigned char *dstBuf = (unsigned char *)malloc(compressedSize);
    if (dstBuf) {
        int pitch = width * pixelSize;
        int result = tjCompress(handle, srcBuf, width, pitch, height, pixelSize, dstBuf, &compressedSize, TJSAMP_444, 75, 0);
        if (result == 0) {
            // Successfully compressed
        }
        free(dstBuf);
    }
}

static void fuzz_tjDecodeYUV(tjhandle handle, const unsigned char *srcBuf, int width, int height, int pixelFormat, size_t dataSize) {
    size_t bufferSize = width * height * tjPixelSize[pixelFormat];
    unsigned char *dstBuf = (unsigned char *)malloc(bufferSize);
    if (dstBuf) {
        if (dataSize >= tjBufSizeYUV(width, height, TJSAMP_444)) {
            int result = tjDecodeYUV(handle, srcBuf, 4, TJSAMP_444, dstBuf, width, width * tjPixelSize[pixelFormat], height, pixelFormat, 0);
            if (result == 0) {
                // Successfully decoded YUV
            }
        }
        free(dstBuf);
    }
}

static void fuzz_tjDecodeYUVPlanes(tjhandle handle, const unsigned char **srcPlanes, const int *strides, int width, int height, int pixelFormat, size_t dataSize) {
    size_t bufferSize = width * height * tjPixelSize[pixelFormat];
    unsigned char *dstBuf = (unsigned char *)malloc(bufferSize);
    if (dstBuf) {
        if (dataSize >= tjBufSizeYUV(width, height, TJSAMP_444)) {
            int result = tjDecodeYUVPlanes(handle, srcPlanes, strides, TJSAMP_444, dstBuf, width, width * tjPixelSize[pixelFormat], height, pixelFormat, 0);
            if (result == 0) {
                // Successfully decoded YUV planes
            }
        }
        free(dstBuf);
    }
}

static void fuzz_tjAlloc(int bytes) {
    unsigned char *buffer = tjAlloc(bytes);
    if (buffer) {
        // Successfully allocated
        tjFree(buffer);
    }
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;  // Ensure enough data for width, height, subsamp

    int width = Data[0] + 1;  // Avoid zero width
    int height = Data[1] + 1; // Avoid zero height
    int subsamp = Data[2] % TJSAMP_440; // Valid subsampling format
    int pixelSize = Data[3] % 4 + 1;  // Ensure pixelSize is between 1 and 4

    fuzz_tjBufSizeYUV(width, height, subsamp);

    tjhandle handle = tjInitDecompress();
    if (handle) {
        fuzz_tjDecompressHeader2(handle, (unsigned char *)Data, Size);
        fuzz_tjCompress(handle, (unsigned char *)Data, width, height, pixelSize);
        fuzz_tjDecodeYUV(handle, Data, width, height, pixelSize, Size);

        const unsigned char *srcPlanes[3] = {Data, Data, Data};
        int strides[3] = {width, width / 2, width / 2};
        fuzz_tjDecodeYUVPlanes(handle, srcPlanes, strides, width, height, pixelSize, Size);

        tjDestroy(handle);
    }

    fuzz_tjAlloc(Size);

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
    