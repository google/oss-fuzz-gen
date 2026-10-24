// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjTransform at turbojpeg.c:3044:15 in turbojpeg.h
// tjDecompressToYUV2 at turbojpeg.c:2404:15 in turbojpeg.h
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
#include <iostream>
#include <fstream>

static void writeToFile(const char* filename, const uint8_t* data, size_t size) {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
    }
}

static void fuzz_tjDecompressHeader2(tjhandle handle, const uint8_t* Data, size_t Size) {
    int width = 0, height = 0, subsamp = 0;
    tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &subsamp);
}

static void fuzz_tjCompress(tjhandle handle, const uint8_t* Data, size_t Size) {
    if (Size < 3) return; // Ensure we have enough data for width, height, and pixelSize
    int width = Data[0], height = Data[1], pixelSize = Data[2];
    if (Size < static_cast<size_t>(width * height * pixelSize)) return;

    unsigned long compressedSize = tjBufSize(width, height, TJSAMP_444);
    unsigned char* dstBuf = static_cast<unsigned char*>(malloc(compressedSize));
    if (!dstBuf) return;

    tjCompress(handle, const_cast<unsigned char*>(Data), width, 0, height, pixelSize, dstBuf, &compressedSize, TJSAMP_444, 75, 0);

    free(dstBuf);
}

static void fuzz_tjDecompress2(tjhandle handle, const uint8_t* Data, size_t Size) {
    int width = 100, height = 100; // Default dimensions
    unsigned char* dstBuf = static_cast<unsigned char*>(malloc(width * height * 3)); // Assuming RGB output
    if (!dstBuf) return;

    tjDecompress2(handle, Data, Size, dstBuf, width, 0, height, TJPF_RGB, 0);

    free(dstBuf);
}

static void fuzz_tjTransform(tjhandle handle, const uint8_t* Data, size_t Size) {
    unsigned char* dstBufs[1];
    unsigned long dstSizes[1] = {Size * 2};
    tjtransform transforms[1] = {0};

    dstBufs[0] = static_cast<unsigned char*>(malloc(dstSizes[0]));
    if (!dstBufs[0]) return;

    tjTransform(handle, Data, Size, 1, dstBufs, dstSizes, transforms, 0);

    free(dstBufs[0]);
}

static void fuzz_tjDecompressToYUV2(tjhandle handle, const uint8_t* Data, size_t Size) {
    int width = 100, height = 100; // Default dimensions
    unsigned char* dstBuf = static_cast<unsigned char*>(malloc(width * height * 3 / 2)); // YUV buffer size
    if (!dstBuf) return;

    tjDecompressToYUV2(handle, Data, Size, dstBuf, width, 4, height, 0);

    free(dstBuf);
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t* Data, size_t Size) {
    if (Size == 0) return 0;

    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    fuzz_tjDecompressHeader2(handle, Data, Size);
    fuzz_tjCompress(handle, Data, Size);
    fuzz_tjDecompress2(handle, Data, Size);
    fuzz_tjTransform(handle, Data, Size);
    fuzz_tjDecompressToYUV2(handle, Data, Size);

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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    