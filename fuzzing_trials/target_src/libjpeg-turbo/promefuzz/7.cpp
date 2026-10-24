// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tj3EncodeYUV8 at turbojpeg.c:1688:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tj3CompressFromYUV8 at turbojpeg.c:1429:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tj3DecodeYUV8 at turbojpeg.c:2678:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tj3EncodeYUVPlanes8 at turbojpeg.c:1508:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjEncodeYUV3 at turbojpeg.c:1734:15 in turbojpeg.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

static tjhandle initializeTurboJPEG() {
    tjhandle handle = tjInitCompress();
    if (!handle) {
        std::cerr << "Failed to initialize TurboJPEG compressor: " << tjGetErrorStr() << std::endl;
        exit(EXIT_FAILURE);
    }
    return handle;
}

static void cleanupTurboJPEG(tjhandle handle) {
    if (tjDestroy(handle) < 0) {
        std::cerr << "Failed to destroy TurboJPEG handle: " << tjGetErrorStr() << std::endl;
    }
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 12) return 0;  // Ensure there's enough data for basic parameters

    tjhandle handle = initializeTurboJPEG();

    // Extract parameters from Data
    int width = Data[0] + 1;
    int height = Data[1] + 1;
    int align = 1 << (Data[2] % 4);  // Ensure align is a power of 2
    int pixelFormat = Data[3] % TJPF_XBGR;  // Use a valid pixel format
    int subsamp = Data[4] % TJSAMP_444;  // Use a valid subsampling option

    unsigned char *srcBuf = const_cast<unsigned char*>(Data + 12);
    size_t srcSize = Size - 12;

    // Calculate buffer sizes
    size_t yuvBufSize = tj3YUVBufSize(width, align, height, subsamp);
    if (yuvBufSize == 0 || yuvBufSize > srcSize) {
        cleanupTurboJPEG(handle);
        return 0;
    }

    unsigned char *yuvBuf = (unsigned char *)malloc(yuvBufSize);
    if (!yuvBuf) {
        std::cerr << "Failed to allocate YUV buffer" << std::endl;
        cleanupTurboJPEG(handle);
        return 0;
    }

    // Fuzz tj3EncodeYUV8
    if (tj3EncodeYUV8(handle, srcBuf, width, 0, height, pixelFormat, yuvBuf, align) < 0) {
        std::cerr << "Error in tj3EncodeYUV8: " << tjGetErrorStr() << std::endl;
    }

    // Fuzz tj3CompressFromYUV8
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;
    if (tj3CompressFromYUV8(handle, yuvBuf, width, align, height, &jpegBuf, &jpegSize) < 0) {
        std::cerr << "Error in tj3CompressFromYUV8: " << tjGetErrorStr() << std::endl;
    }

    // Fuzz tj3DecodeYUV8
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (dstBuf) {
        if (tj3DecodeYUV8(handle, yuvBuf, align, dstBuf, width, 0, height, pixelFormat) < 0) {
            std::cerr << "Error in tj3DecodeYUV8: " << tjGetErrorStr() << std::endl;
        }
        free(dstBuf);
    }

    // Fuzz tj3EncodeYUVPlanes8
    unsigned char *dstPlanes[3] = { nullptr, nullptr, nullptr };
    int strides[3] = { width, width / 2, width / 2 };
    for (int i = 0; i < 3; i++) {
        dstPlanes[i] = (unsigned char *)malloc(strides[i] * height);
    }
    if (tj3EncodeYUVPlanes8(handle, srcBuf, width, 0, height, pixelFormat, dstPlanes, strides) < 0) {
        std::cerr << "Error in tj3EncodeYUVPlanes8: " << tjGetErrorStr() << std::endl;
    }
    for (int i = 0; i < 3; i++) {
        free(dstPlanes[i]);
    }

    // Fuzz tjEncodeYUV3
    unsigned char *yuv3Buf = (unsigned char *)malloc(yuvBufSize);
    if (yuv3Buf) {
        if (tjEncodeYUV3(handle, srcBuf, width, 0, height, pixelFormat, yuv3Buf, align, subsamp, 0) < 0) {
            std::cerr << "Error in tjEncodeYUV3: " << tjGetErrorStr() << std::endl;
        }
        free(yuv3Buf);
    }

    if (jpegBuf) tjFree(jpegBuf);
    free(yuvBuf);
    cleanupTurboJPEG(handle);

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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    