// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3SaveImage16 at turbojpeg-mp.c:487:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tjLoadImage at turbojpeg.c:3107:26 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tjGetErrorStr2 at turbojpeg.c:630:17 in turbojpeg.h
// tj3LoadImage16 at turbojpeg-mp.c:434:21 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tjSaveImage at turbojpeg.c:3128:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Dummy file preparation
    FILE *dummyFile = fopen("./dummy_file", "wb");
    if (!dummyFile) return 0;
    fwrite(Data, 1, Size, dummyFile);
    fclose(dummyFile);

    // Initialize variables
    tjhandle handle = nullptr;
    int width = 0, height = 0, pixelFormat = 0, align = 1, flags = 0;
    unsigned char *imageBuffer = nullptr;
    unsigned short *imageBuffer16 = nullptr;

    // Test tj3GetErrorStr
    char *errorStr = tj3GetErrorStr(handle);
    if (errorStr) {
        printf("tj3GetErrorStr: %s\n", errorStr);
    }

    // Test tj3SaveImage16
    int result = tj3SaveImage16(handle, "./dummy_file", reinterpret_cast<unsigned short*>(const_cast<uint8_t*>(Data)),
                                10, 0, 10, TJPF_RGB);
    if (result == -1) {
        errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            printf("tj3SaveImage16 Error: %s\n", errorStr);
        }
    }

    // Test tjLoadImage
    imageBuffer = tjLoadImage("./dummy_file", &width, align, &height, &pixelFormat, flags);
    if (imageBuffer) {
        tjFree(imageBuffer);
    } else {
        errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            printf("tjLoadImage Error: %s\n", errorStr);
        }
    }

    // Test tjGetErrorStr2
    errorStr = tjGetErrorStr2(handle);
    if (errorStr) {
        printf("tjGetErrorStr2: %s\n", errorStr);
    }

    // Test tj3LoadImage16
    imageBuffer16 = tj3LoadImage16(handle, "./dummy_file", &width, align, &height, &pixelFormat);
    if (imageBuffer16) {
        tj3Free(imageBuffer16);
    } else {
        errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            printf("tj3LoadImage16 Error: %s\n", errorStr);
        }
    }

    // Test tjSaveImage
    result = tjSaveImage("./dummy_file", reinterpret_cast<unsigned char*>(const_cast<uint8_t*>(Data)),
                         10, 0, 10, TJPF_RGB, flags);
    if (result == -1) {
        errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            printf("tjSaveImage Error: %s\n", errorStr);
        }
    }

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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    