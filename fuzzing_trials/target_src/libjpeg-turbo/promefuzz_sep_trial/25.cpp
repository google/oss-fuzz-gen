// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjSaveImage at turbojpeg.c:3128:15 in turbojpeg.h
// tjLoadImage at turbojpeg.c:3107:26 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tj3SaveImage16 at turbojpeg-mp.c:487:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
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
#include <exception>
#include <iostream>

static void handleError(const char* context) {
    std::cerr << "Error during " << context << ": " << tjGetErrorStr() << std::endl;
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz tjSaveImage
    {
        const char* filename = "./dummy_file";
        int width = 10; // Adjusted to smaller size for safety
        int height = 10; // Adjusted to smaller size for safety
        int pitch = width * tjPixelSize[TJPF_RGB];
        int pixelFormat = TJPF_RGB;
        int flags = 0;

        if (Size < static_cast<size_t>(pitch * height)) {
            return 0; // Ensure buffer is large enough
        }

        unsigned char* buffer = const_cast<unsigned char*>(Data);

        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
        }

        if (tjSaveImage(filename, buffer, width, pitch, height, pixelFormat, flags) == -1) {
            handleError("tjSaveImage");
        }
    }

    // Fuzz tjLoadImage
    {
        const char* filename = "./dummy_file";
        int width = 0, height = 0, pixelFormat = 0;
        int align = 1;
        int flags = 0;

        unsigned char* imageBuffer = tjLoadImage(filename, &width, align, &height, &pixelFormat, flags);
        if (imageBuffer == nullptr) {
            handleError("tjLoadImage");
        } else {
            tjFree(imageBuffer);
        }
    }

    // Fuzz tj3SaveImage16
    {
        tjhandle handle = tjInitCompress();
        const char* filename = "./dummy_file";
        int width = 10; // Adjusted to smaller size for safety
        int height = 10; // Adjusted to smaller size for safety
        int pitch = width * tjPixelSize[TJPF_RGB];

        if (Size < static_cast<size_t>(pitch * height * sizeof(unsigned short))) {
            tjDestroy(handle);
            return 0; // Ensure buffer is large enough
        }

        const unsigned short* buffer = reinterpret_cast<const unsigned short*>(Data);
        int pixelFormat = TJPF_RGB;

        if (tj3SaveImage16(handle, filename, buffer, width, pitch, height, pixelFormat) == -1) {
            handleError("tj3SaveImage16");
        }

        tjDestroy(handle);
    }

    // Fuzz tjCompress
    {
        tjhandle handle = tjInitCompress();
        int width = 10; // Adjusted to smaller size for safety
        int height = 10; // Adjusted to smaller size for safety
        int pitch = width * tjPixelSize[TJPF_RGB];
        int pixelSize = 3;

        if (Size < static_cast<size_t>(pitch * height)) {
            tjDestroy(handle);
            return 0; // Ensure buffer is large enough
        }

        unsigned char* srcBuf = const_cast<unsigned char*>(Data);
        unsigned char* dstBuf = nullptr;
        unsigned long compressedSize = 0;
        int jpegSubsamp = TJSAMP_444;
        int jpegQual = 75;
        int flags = 0;

        if (tjCompress(handle, srcBuf, width, pitch, height, pixelSize, dstBuf, &compressedSize, jpegSubsamp, jpegQual, flags) == -1) {
            handleError("tjCompress");
        }

        tjDestroy(handle);
    }

    // Fuzz tjAlloc
    {
        int bytes = 1024;
        unsigned char* allocatedBuffer = tjAlloc(bytes);
        if (allocatedBuffer == nullptr) {
            handleError("tjAlloc");
        } else {
            tjFree(allocatedBuffer);
        }
    }

    // Fuzz tjDecompress2
    {
        tjhandle handle = tjInitDecompress();
        const unsigned char* jpegBuf = Data;
        unsigned long jpegSize = Size;
        int width = 10; // Adjusted to smaller size for safety
        int height = 10; // Adjusted to smaller size for safety
        int pitch = width * tjPixelSize[TJPF_RGB];

        if (Size < static_cast<size_t>(pitch * height)) {
            tjDestroy(handle);
            return 0; // Ensure buffer is large enough
        }

        unsigned char* dstBuf = tjAlloc(pitch * height);
        int pixelFormat = TJPF_RGB;
        int flags = 0;

        if (tjDecompress2(handle, jpegBuf, jpegSize, dstBuf, width, pitch, height, pixelFormat, flags) == -1) {
            handleError("tjDecompress2");
        }

        tjFree(dstBuf);
        tjDestroy(handle);
    }

    return 0;
}