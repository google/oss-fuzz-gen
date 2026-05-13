// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjGetErrorStr2 at turbojpeg.c:630:17 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tj3SaveImage16 at turbojpeg-mp.c:487:15 in turbojpeg.h
// tjLoadImage at turbojpeg.c:3107:26 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjGetErrorStr2 at turbojpeg.c:630:17 in turbojpeg.h
// tj3LoadImage16 at turbojpeg-mp.c:434:21 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tjSaveImage at turbojpeg.c:3128:15 in turbojpeg.h
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

static void handleTJError(tjhandle handle) {
    const char *errorStr = tjGetErrorStr2(handle);
    if (errorStr) {
        fprintf(stderr, "TurboJPEG error: %s\n", errorStr);
    }
}

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 4) {
        return 0;
    }

    // Fuzz tj3GetErrorStr
    tjhandle handle = nullptr;
    char *errorStr = tj3GetErrorStr(handle);
    if (errorStr) {
        printf("Error: %s\n", errorStr);
    }

    // Extract parameters safely
    int width = *reinterpret_cast<const int*>(Data);
    int pitch = *reinterpret_cast<const int*>(Data + sizeof(int));
    int height = *reinterpret_cast<const int*>(Data + sizeof(int) * 2);
    int pixelFormat = *reinterpret_cast<const int*>(Data + sizeof(int) * 3);

    // Ensure parameters are reasonable
    if (width <= 0 || height <= 0 || pitch <= 0 || width > 10000 || height > 10000) {
        return 0;
    }

    // Calculate buffer size safely
    size_t bufferSize = static_cast<size_t>(pitch) * height * sizeof(unsigned short);
    if (bufferSize > Size) {
        return 0;
    }

    // Fuzz tj3SaveImage16
    handle = tjInitCompress();
    if (!handle) {
        handleTJError(handle);
        return 0;
    }
    
    const char *filename = "./dummy_file";
    unsigned short *buffer = reinterpret_cast<unsigned short*>(const_cast<uint8_t*>(Data));

    int saveResult = tj3SaveImage16(handle, filename, buffer, width, pitch, height, pixelFormat);
    if (saveResult == -1) {
        handleTJError(handle);
    }

    // Fuzz tjLoadImage
    int outWidth, outHeight, outPixelFormat;
    unsigned char *loadedImage = tjLoadImage(filename, &outWidth, 1, &outHeight, &outPixelFormat, 0);
    if (!loadedImage) {
        handleTJError(handle);
    } else {
        tjFree(loadedImage);
    }

    // Fuzz tjGetErrorStr2
    errorStr = tjGetErrorStr2(handle);
    if (errorStr) {
        printf("Error: %s\n", errorStr);
    }

    // Fuzz tj3LoadImage16
    int align = 1;
    unsigned short *loadedImage16 = tj3LoadImage16(handle, filename, &outWidth, align, &outHeight, &outPixelFormat);
    if (!loadedImage16) {
        handleTJError(handle);
    } else {
        tj3Free(loadedImage16);
    }

    // Fuzz tjSaveImage
    size_t buffer8Size = static_cast<size_t>(pitch) * height;
    if (buffer8Size <= Size) {
        unsigned char *buffer8 = reinterpret_cast<unsigned char*>(const_cast<uint8_t*>(Data));
        int saveImageResult = tjSaveImage(filename, buffer8, width, pitch, height, pixelFormat, 0);
        if (saveImageResult == -1) {
            handleTJError(handle);
        }
    }

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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    