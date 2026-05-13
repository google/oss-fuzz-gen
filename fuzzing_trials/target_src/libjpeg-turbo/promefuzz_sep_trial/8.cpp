// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tj3CompressFromYUV8 at turbojpeg.c:1429:15 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3DecompressToYUV8 at turbojpeg.c:2341:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
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
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    int width = Data[0] + 1;
    int align = 1 << (Data[1] % 4);  // Power of 2 alignment
    int height = Data[2] + 1;
    int subsamp = Data[3] % 6;  // Assuming 6 subsampling options

    size_t yuvBufSize = tj3YUVBufSize(width, align, height, subsamp);
    if (yuvBufSize == 0) return 0;

    unsigned char *yuvBuf = (unsigned char *)malloc(yuvBufSize);
    if (!yuvBuf) return 0;

    tjhandle handle = tjInitCompress();
    if (!handle) {
        free(yuvBuf);
        return 0;
    }

    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;
    if (tj3CompressFromYUV8(handle, yuvBuf, width, align, height, &jpegBuf, &jpegSize) == 0) {
        unsigned char *dstBuf = (unsigned char *)malloc(yuvBufSize);
        if (dstBuf) {
            tjhandle decompressHandle = tjInitDecompress();
            if (decompressHandle) {
                tj3DecompressToYUV8(decompressHandle, jpegBuf, jpegSize, dstBuf, align);
                tjDestroy(decompressHandle);
            }
            free(dstBuf);
        }
        tjFree(jpegBuf);
    }

    tjDestroy(handle);
    free(yuvBuf);

    return 0;
}