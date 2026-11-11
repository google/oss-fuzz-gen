// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjLoadImage at turbojpeg.c:3107:26 in turbojpeg.h
// tjSaveImage at turbojpeg.c:3128:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tj3SaveImage16 at turbojpeg-mp.c:487:15 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy file for tjLoadImage and tjSaveImage
    const char *dummyFile = "./dummy_file";
    FILE *file = fopen(dummyFile, "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Variables for tjLoadImage
    int width = 0, height = 0, pixelFormat = 0;
    unsigned char *imageBuffer = nullptr;

    // Fuzz tjLoadImage
    imageBuffer = tjLoadImage(dummyFile, &width, 1, &height, &pixelFormat, 0);
    if (imageBuffer) {
        // Fuzz tjSaveImage
        tjSaveImage(dummyFile, imageBuffer, width, width * tjPixelSize[pixelFormat], height, pixelFormat, 0);
        tjFree(imageBuffer);
    }

    // Variables for tj3SaveImage16
    tjhandle handle = nullptr;
    unsigned short *buffer16 = reinterpret_cast<unsigned short*>(malloc(Size * sizeof(unsigned short)));
    if (buffer16) {
        memcpy(buffer16, Data, Size);
        tj3SaveImage16(handle, dummyFile, buffer16, width, width, height, pixelFormat);
        free(buffer16);
    }

    // Buffer for tjCompress
    unsigned char *compressedBuf = nullptr;
    unsigned long compressedSize = 0;

    // Fuzz tjCompress
    tjhandle compressHandle = tjInitCompress();
    if (compressHandle) {
        compressedBuf = tjAlloc(tjBufSize(width, height, pixelFormat));
        if (compressedBuf) {
            tjCompress(compressHandle, imageBuffer, width, width * tjPixelSize[pixelFormat], height, tjPixelSize[pixelFormat],
                       compressedBuf, &compressedSize, TJSAMP_444, 75, 0);
            tjFree(compressedBuf);
        }
        tjDestroy(compressHandle);
    }

    // Buffer for tjDecompress2
    unsigned char *decompressedBuf = nullptr;

    // Fuzz tjDecompress2
    tjhandle decompressHandle = tjInitDecompress();
    if (decompressHandle) {
        decompressedBuf = tjAlloc(width * height * tjPixelSize[pixelFormat]);
        if (decompressedBuf) {
            tjDecompress2(decompressHandle, Data, Size, decompressedBuf, width, width * tjPixelSize[pixelFormat], height, pixelFormat, 0);
            tjFree(decompressedBuf);
        }
        tjDestroy(decompressHandle);
    }

    return 0;
}