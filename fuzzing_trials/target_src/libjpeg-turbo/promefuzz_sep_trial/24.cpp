// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjDecompressToYUV2 at turbojpeg.c:2404:15 in turbojpeg.h
// tjTransform at turbojpeg.c:3044:15 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a TurboJPEG decompression handle
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    // Allocate buffers for decompression output
    int width = 0, height = 0, jpegSubsamp = 0;
    if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &jpegSubsamp) == -1) {
        tjDestroy(handle);
        return 0;
    }

    unsigned char *yuvBuf = (unsigned char *)malloc(width * height * 3 / 2);
    if (!yuvBuf) {
        tjDestroy(handle);
        return 0;
    }

    // Fuzz tjDecompressToYUV2
    tjDecompressToYUV2(handle, const_cast<unsigned char*>(Data), Size, yuvBuf, width, 4, height, 0);

    // Fuzz tjTransform
    unsigned char *dstBufs[1] = { nullptr };
    unsigned long dstSizes[1] = { 0 };
    tjtransform transform = { 0 };
    tjTransform(handle, const_cast<unsigned char*>(Data), Size, 1, dstBufs, dstSizes, &transform, 0);

    // Fuzz tjCompress
    unsigned long compressedSize = 0;
    unsigned char *compressedBuf = nullptr;
    tjCompress(handle, yuvBuf, width, width * 3, height, 3, compressedBuf, &compressedSize, jpegSubsamp, 75, 0);

    // Fuzz tjDecompress2
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * 3);
    if (dstBuf) {
        tjDecompress2(handle, const_cast<unsigned char*>(Data), Size, dstBuf, width, width * 3, height, TJPF_RGB, 0);
        free(dstBuf);
    }

    // Fuzz tj3GetErrorCode
    tj3GetErrorCode(handle);

    // Clean up
    if (compressedBuf) tjFree(compressedBuf);
    if (dstBufs[0]) tjFree(dstBufs[0]);
    free(yuvBuf);
    tjDestroy(handle);

    return 0;
}