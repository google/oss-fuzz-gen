// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjEncodeYUV at turbojpeg.c:1767:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjCompressFromYUV at turbojpeg.c:1476:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjCompress2 at turbojpeg.c:1204:15 in turbojpeg.h
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

static tjhandle initializeHandle() {
    tjhandle handle = tjInitCompress();
    if (!handle) {
        std::cerr << "Failed to initialize TurboJPEG handle" << std::endl;
    }
    return handle;
}

static void cleanupHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = initializeHandle();
    if (!handle) return 0;

    unsigned char *srcBuf = (unsigned char *)malloc(Size);
    if (!srcBuf) {
        cleanupHandle(handle);
        return 0;
    }
    memcpy(srcBuf, Data, Size);

    int width = 256;
    int height = 256;
    int pixelSize = 3;
    int pitch = width * pixelSize;
    unsigned long compressedSize = 0;
    unsigned char *dstBuf = nullptr;

    // Fuzz tjCompress
    int ret = tjCompress(handle, srcBuf, width, pitch, height, pixelSize, dstBuf, &compressedSize, TJSAMP_444, 75, 0);
    if (ret != 0) {
        std::cerr << "tjCompress failed: " << tjGetErrorStr() << std::endl;
    }

    // Fuzz tjEncodeYUV
    int yuvSize = tjBufSizeYUV2(width, pitch, height, TJSAMP_444);
    unsigned char *yuvBuf = (unsigned char *)malloc(yuvSize);
    if (yuvBuf) {
        ret = tjEncodeYUV(handle, srcBuf, width, pitch, height, pixelSize, yuvBuf, TJSAMP_444, 0);
        if (ret != 0) {
            std::cerr << "tjEncodeYUV failed: " << tjGetErrorStr() << std::endl;
        }
        free(yuvBuf);
    }

    // Fuzz tjDecompress2
    unsigned char *decompressedBuf = (unsigned char *)malloc(width * height * pixelSize);
    if (decompressedBuf) {
        ret = tjDecompress2(handle, srcBuf, Size, decompressedBuf, width, pitch, height, TJPF_RGB, 0);
        if (ret != 0) {
            std::cerr << "tjDecompress2 failed: " << tjGetErrorStr() << std::endl;
        }
        free(decompressedBuf);
    }

    // Fuzz tjCompressFromYUV
    int yuvAlign = 4; // Ensure alignment
    int yuvPlaneSize = tjBufSizeYUV2(width, yuvAlign, height, TJSAMP_444);
    unsigned char *yuvSrcBuf = (unsigned char *)malloc(yuvPlaneSize);
    if (yuvSrcBuf) {
        // Initialize YUV buffer with valid data
        memset(yuvSrcBuf, 0, yuvPlaneSize);
        unsigned char *jpegBuf = nullptr;
        unsigned long jpegSize = 0;
        ret = tjCompressFromYUV(handle, yuvSrcBuf, width, yuvAlign, height, TJSAMP_444, &jpegBuf, &jpegSize, 75, 0);
        if (ret != 0) {
            std::cerr << "tjCompressFromYUV failed: " << tjGetErrorStr() << std::endl;
        }
        if (jpegBuf) {
            tjFree(jpegBuf);
        }
        free(yuvSrcBuf);
    }

    // Fuzz tjCompress2
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    ret = tjCompress2(handle, srcBuf, width, pitch, height, TJPF_RGB, &jpegBuf, &jpegSize, TJSAMP_444, 75, 0);
    if (ret != 0) {
        std::cerr << "tjCompress2 failed: " << tjGetErrorStr() << std::endl;
    }
    if (jpegBuf) {
        tjFree(jpegBuf);
    }

    free(srcBuf);
    cleanupHandle(handle);
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    