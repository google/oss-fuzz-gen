// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjDecodeYUV at turbojpeg.c:2724:15 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tjGetErrorCode at turbojpeg.c:652:15 in turbojpeg.h
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
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
#include <iostream>

static void fuzz_tjDecodeYUV(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    int align = 1 + (Data[0] % 4); // Alignment should be 1, 2, or 4
    int subsamp = Data[0] % 6; // Valid subsampling (0-5)
    int width = 100; // Example width
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int flags = 0; // Example flags
    size_t dstBufSize = width * height * tjPixelSize[pixelFormat];
    unsigned char *dstBuf = (unsigned char *)malloc(dstBufSize);

    if (dstBuf) {
        if (Size >= tjBufSizeYUV2(width, align, height, subsamp)) {
            tjDecodeYUV(handle, Data, align, subsamp, dstBuf, width, width * tjPixelSize[pixelFormat], height, pixelFormat, flags);
        }
        free(dstBuf);
    }
}

static void fuzz_tjDecompressHeader2(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    int width = 0, height = 0, subsamp = 0;
    tjDecompressHeader2(handle, const_cast<unsigned char *>(Data), Size, &width, &height, &subsamp);
}

static void fuzz_tjCompressFromYUVPlanes(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    int width = 100; // Example width
    int height = 100; // Example height
    int subsamp = Data[0] % 6; // Valid subsampling (0-5)
    int jpegQual = Data[0] % 100; // Quality (0-100)
    int flags = 0; // Example flags
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    const unsigned char *srcPlanes[3] = {Data, Data, Data};
    int strides[3] = {width, width / 2, width / 2};

    if (Size >= tjBufSizeYUV2(width, 1, height, subsamp)) {
        tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);
    }
    tjFree(jpegBuf);
}

static void fuzz_tjDecodeYUVPlanes(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    int width = 100; // Example width
    int height = 100; // Example height
    int subsamp = Data[0] % 6; // Valid subsampling (0-5)
    int pixelFormat = TJPF_RGB; // Example pixel format
    int flags = 0; // Example flags
    size_t dstBufSize = width * height * tjPixelSize[pixelFormat];
    unsigned char *dstBuf = (unsigned char *)malloc(dstBufSize);

    if (dstBuf) {
        const unsigned char *srcPlanes[3] = {Data, Data, Data};
        int strides[3] = {width, width / 2, width / 2};

        if (Size >= tjBufSizeYUV2(width, 1, height, subsamp)) {
            tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, dstBuf, width, width * tjPixelSize[pixelFormat], height, pixelFormat, flags);
        }
        free(dstBuf);
    }
}

static void fuzz_tjGetErrorCode(tjhandle handle) {
    tjGetErrorCode(handle);
}

static void fuzz_tj3GetErrorCode(tjhandle handle) {
    tj3GetErrorCode(handle);
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    fuzz_tjDecodeYUV(handle, Data, Size);
    fuzz_tjDecompressHeader2(handle, Data, Size);
    fuzz_tjCompressFromYUVPlanes(handle, Data, Size);
    fuzz_tjDecodeYUVPlanes(handle, Data, Size);
    fuzz_tjGetErrorCode(handle);
    fuzz_tj3GetErrorCode(handle);

    tjDestroy(handle);
    return 0;
}