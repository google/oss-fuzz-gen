// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjDecompressToYUV2 at turbojpeg.c:2404:15 in turbojpeg.h
// tjTransform at turbojpeg.c:3044:15 in turbojpeg.h
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    int width = 0, height = 0, jpegSubsamp = 0;
    if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &jpegSubsamp) == 0) {
        unsigned char *dstBuf = (unsigned char *)malloc(width * height * 3);
        if (dstBuf) {
            tjDecompress2(handle, Data, Size, dstBuf, width, width * 3, height, TJPF_RGB, 0);
            free(dstBuf);
        }
    }

    unsigned long compressedSize = 0;
    unsigned char *compressedBuf = nullptr;
    int pixelSize = 3; // Assuming RGB format
    if (Size >= width * height * pixelSize) {
        compressedBuf = (unsigned char *)malloc(tjBufSize(width, height, jpegSubsamp));
        if (compressedBuf) {
            tjCompress(handle, const_cast<unsigned char*>(Data), width, width * pixelSize, height, pixelSize, compressedBuf, &compressedSize, jpegSubsamp, 75, 0);
            free(compressedBuf);
        }
    }

    int align = 1; // Default alignment
    unsigned char *yuvBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, align, height, jpegSubsamp));
    if (yuvBuf) {
        tjDecompressToYUV2(handle, Data, Size, yuvBuf, width, align, height, 0);
        free(yuvBuf);
    }

    tjtransform transform;
    memset(&transform, 0, sizeof(transform));
    unsigned char *dstBufs[1] = { nullptr };
    unsigned long dstSizes[1] = { 0 };
    tjTransform(handle, Data, Size, 1, dstBufs, dstSizes, &transform, 0);

    tj3GetErrorCode(handle);

    tjDestroy(handle);
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

        LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    