// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjLoadImage at turbojpeg.c:3107:26 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompress at turbojpeg.c:2111:15 in turbojpeg.h
// tjGetErrorStr2 at turbojpeg.c:630:17 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjGetErrorStr2 at turbojpeg.c:630:17 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjSaveImage at turbojpeg.c:3128:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write the input data to a dummy file
    const char* dummyFilename = "./dummy_file";
    FILE* file = fopen(dummyFilename, "wb");
    if (!file) return 0;

    fwrite(Data, 1, Size, file);
    fclose(file);

    // Variables for tjLoadImage
    int width = 0, height = 0, pixelFormat = 0;
    unsigned char* imageBuf = tjLoadImage(dummyFilename, &width, 1, &height, &pixelFormat, 0);
    if (imageBuf) {
        tjFree(imageBuf);
    } else {
        char* errorStr = tjGetErrorStr();
        if (errorStr) printf("tjLoadImage error: %s\n", errorStr);
    }

    // Variables for tjDecompress and tjDecompress2
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    unsigned char* dstBuf = (unsigned char*)malloc(width * height * tjPixelSize[pixelFormat]);
    if (dstBuf) {
        int decompressResult = tjDecompress(handle, (unsigned char*)Data, Size, dstBuf, width, 0, height, tjPixelSize[pixelFormat], 0);
        if (decompressResult != 0) {
            char* errorStr2 = tjGetErrorStr2(handle);
            if (errorStr2) printf("tjDecompress error: %s\n", errorStr2);
        }

        int decompress2Result = tjDecompress2(handle, (unsigned char*)Data, Size, dstBuf, width, 0, height, pixelFormat, 0);
        if (decompress2Result != 0) {
            char* errorStr2 = tjGetErrorStr2(handle);
            if (errorStr2) printf("tjDecompress2 error: %s\n", errorStr2);
        }

        free(dstBuf);
    }

    tjDestroy(handle);

    // Variables for tjSaveImage
    unsigned char* saveBuf = (unsigned char*)malloc(width * height * tjPixelSize[pixelFormat]);
    if (saveBuf) {
        int saveResult = tjSaveImage(dummyFilename, saveBuf, width, 0, height, pixelFormat, 0);
        if (saveResult != 0) {
            char* errorStr = tjGetErrorStr();
            if (errorStr) printf("tjSaveImage error: %s\n", errorStr);
        }
        free(saveBuf);
    }

    return 0;
}