// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjTransform at turbojpeg.c:3044:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDecompressToYUV2 at turbojpeg.c:2404:15 in turbojpeg.h
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
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

static void fuzz_tjDecompressHeader2(tjhandle handle, const uint8_t *Data, size_t Size) {
    int width = 0, height = 0, jpegSubsamp = 0;
    tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &jpegSubsamp);
}

static void fuzz_tjCompress(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Ensure there's enough data for width/height
    int width = Data[0];
    int height = Data[1];
    int pixelSize = 3; // Assuming RGB
    unsigned long compressedSize = tjBufSize(width, height, TJSAMP_444);
    unsigned char *dstBuf = (unsigned char *)tjAlloc(compressedSize);
    if (dstBuf) {
        tjCompress(handle, const_cast<unsigned char*>(Data), width, width * pixelSize, height, pixelSize, dstBuf, &compressedSize, TJSAMP_444, 75, 0);
        tjFree(dstBuf);
    }
}

static void fuzz_tjDecompress2(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Ensure there's enough data for width/height
    int width = Data[0];
    int height = Data[1];
    int pixelFormat = TJPF_RGB;
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (dstBuf) {
        tjDecompress2(handle, Data, Size, dstBuf, width, 0, height, pixelFormat, 0);
        free(dstBuf);
    }
}

static void fuzz_tjTransform(tjhandle handle, const uint8_t *Data, size_t Size) {
    unsigned char *dstBufs[1];
    unsigned long dstSizes[1];
    tjtransform transforms[1];
    memset(transforms, 0, sizeof(transforms));
    dstBufs[0] = nullptr;
    dstSizes[0] = 0;
    tjTransform(handle, Data, Size, 1, dstBufs, dstSizes, transforms, 0);
    if (dstBufs[0]) tjFree(dstBufs[0]);
}

static void fuzz_tjDecompressToYUV2(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Ensure there's enough data for width/height
    int width = Data[0];
    int height = Data[1];
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * 3 / 2); // YUV requires 1.5 bytes per pixel
    if (dstBuf) {
        tjDecompressToYUV2(handle, Data, Size, dstBuf, width, 4, height, 0);
        free(dstBuf);
    }
}

static void fuzz_tj3GetErrorCode(tjhandle handle) {
    int errorCode = tj3GetErrorCode(handle);
    (void)errorCode; // Suppress unused variable warning
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    fuzz_tjDecompressHeader2(handle, Data, Size);
    fuzz_tjCompress(handle, Data, Size);
    fuzz_tjDecompress2(handle, Data, Size);
    fuzz_tjTransform(handle, Data, Size);
    fuzz_tjDecompressToYUV2(handle, Data, Size);
    fuzz_tj3GetErrorCode(handle);

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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    