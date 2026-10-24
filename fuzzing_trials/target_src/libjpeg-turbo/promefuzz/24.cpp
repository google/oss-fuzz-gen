// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tj3DecodeYUV8 at turbojpeg.c:2678:15 in turbojpeg.h
// tjDecodeYUV at turbojpeg.c:2724:15 in turbojpeg.h
// tj3DecodeYUVPlanes8 at turbojpeg.c:2511:15 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tj3EncodeYUV8 at turbojpeg.c:1688:15 in turbojpeg.h
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
#include <stdexcept>

static tjhandle initializeHandle() {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        throw std::runtime_error("Failed to initialize TurboJPEG decompressor");
    }
    return handle;
}

static void destroyHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = nullptr;
    try {
        handle = initializeHandle();

        // Prepare dummy variables for function parameters
        int align = 1 << (Data[0] % 3); // 1, 2, or 4
        int width = 16, height = 16, pixelFormat = TJPF_RGB;
        int pitch = width * tjPixelSize[pixelFormat];
        unsigned char *srcBuf = const_cast<unsigned char*>(Data);
        unsigned char *dstBuf = (unsigned char*)malloc(pitch * height);

        // Fuzz tj3DecodeYUV8
        if (Size >= width * height * 3) {
            tj3DecodeYUV8(handle, srcBuf, align, dstBuf, width, pitch, height, pixelFormat);
        }

        // Fuzz tjDecodeYUV
        if (Size >= width * height * 3) {
            int subsamp = TJSAMP_444;
            int flags = 0;
            tjDecodeYUV(handle, srcBuf, align, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);
        }

        // Fuzz tj3DecodeYUVPlanes8
        if (Size >= width * height * 3) {
            const unsigned char *srcPlanes[3] = { srcBuf, srcBuf + width * height, srcBuf + 2 * width * height };
            int strides[3] = { width, width / 2, width / 2 };
            tj3DecodeYUVPlanes8(handle, srcPlanes, strides, dstBuf, width, pitch, height, pixelFormat);
        }

        // Fuzz tjCompressFromYUVPlanes
        if (Size >= width * height * 3) {
            const unsigned char *srcPlanes[3] = { srcBuf, srcBuf + width * height, srcBuf + 2 * width * height };
            int strides[3] = { width, width / 2, width / 2 };
            unsigned char *jpegBuf = nullptr;
            unsigned long jpegSize = 0;
            int subsamp = TJSAMP_444;
            int jpegQual = 75;
            int flags = 0;
            tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);
            tjFree(jpegBuf);
        }

        // Fuzz tjDecodeYUVPlanes
        if (Size >= width * height * 3) {
            const unsigned char *srcPlanes[3] = { srcBuf, srcBuf + width * height, srcBuf + 2 * width * height };
            int strides[3] = { width, width / 2, width / 2 };
            int subsamp = TJSAMP_444;
            int flags = 0;
            tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);
        }

        // Fuzz tj3EncodeYUV8
        if (Size >= pitch * height) {
            unsigned char *yuvBuf = (unsigned char*)malloc(tj3YUVBufSize(width, align, height, TJSAMP_444));
            tj3EncodeYUV8(handle, srcBuf, width, pitch, height, pixelFormat, yuvBuf, align);
            free(yuvBuf);
        }

        free(dstBuf);
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    destroyHandle(handle);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    