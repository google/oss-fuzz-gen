// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjDecompressToYUV2 at turbojpeg.c:2404:15 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjDecompress at turbojpeg.c:2111:15 in turbojpeg.h
// tjDecompressToYUV at turbojpeg.c:2452:15 in turbojpeg.h
// tjDecompressToYUVPlanes at turbojpeg.c:2291:15 in turbojpeg.h
// tj3DecompressToYUV8 at turbojpeg.c:2341:15 in turbojpeg.h
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
#include <exception>

static void fuzz_tj3DecompressToYUV8(const uint8_t *Data, size_t Size) {
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (!handle) return;

    unsigned char *dstBuf = nullptr;
    int align = 4; // Typical alignment for X Video
    size_t jpegSize = Size;

    try {
        if (Size > 0) {
            int width, height, subsamp;
            if (tj3DecompressHeader(handle, Data, jpegSize) == 0) {
                width = tj3Get(handle, TJPARAM_JPEGWIDTH);
                height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
                subsamp = tj3Get(handle, TJPARAM_SUBSAMP);
                size_t bufSize = tj3YUVBufSize(width, align, height, subsamp);
                dstBuf = new unsigned char[bufSize];
                if (tj3DecompressToYUV8(handle, Data, jpegSize, dstBuf, align) != 0) {
                    throw std::runtime_error(tj3GetErrorStr(handle));
                }
            }
        }
    } catch (const std::exception &e) {
        // Handle exceptions
    }

    delete[] dstBuf;
    tj3Destroy(handle);
}

static void fuzz_tjDecompress2(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return;

    unsigned char *dstBuf = nullptr;
    unsigned long jpegSize = static_cast<unsigned long>(Size);

    try {
        if (Size > 0) {
            int width, height, subsamp;
            if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), jpegSize, &width, &height, &subsamp) == 0) {
                int pixelFormat = TJPF_RGB;
                dstBuf = new unsigned char[width * height * tjPixelSize[pixelFormat]];
                if (tjDecompress2(handle, const_cast<unsigned char*>(Data), jpegSize, dstBuf, width, 0, height, pixelFormat, 0) != 0) {
                    throw std::runtime_error(tjGetErrorStr());
                }
            }
        }
    } catch (const std::exception &e) {
        // Handle exceptions
    }

    delete[] dstBuf;
    tjDestroy(handle);
}

static void fuzz_tjDecompressToYUV(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return;

    unsigned char *dstBuf = nullptr;
    unsigned long jpegSize = static_cast<unsigned long>(Size);

    try {
        if (Size > 0) {
            int width, height, subsamp;
            if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), jpegSize, &width, &height, &subsamp) == 0) {
                size_t bufSize = tjBufSizeYUV2(width, 4, height, subsamp);
                dstBuf = new unsigned char[bufSize];
                if (tjDecompressToYUV(handle, const_cast<unsigned char*>(Data), jpegSize, dstBuf, 0) != 0) {
                    throw std::runtime_error(tjGetErrorStr());
                }
            }
        }
    } catch (const std::exception &e) {
        // Handle exceptions
    }

    delete[] dstBuf;
    tjDestroy(handle);
}

static void fuzz_tjDecompressToYUV2(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return;

    unsigned char *dstBuf = nullptr;
    unsigned long jpegSize = static_cast<unsigned long>(Size);

    try {
        if (Size > 0) {
            int width, height, subsamp;
            if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), jpegSize, &width, &height, &subsamp) == 0) {
                size_t bufSize = tjBufSizeYUV2(width, 4, height, subsamp);
                dstBuf = new unsigned char[bufSize];
                if (tjDecompressToYUV2(handle, const_cast<unsigned char*>(Data), jpegSize, dstBuf, width, 4, height, 0) != 0) {
                    throw std::runtime_error(tjGetErrorStr());
                }
            }
        }
    } catch (const std::exception &e) {
        // Handle exceptions
    }

    delete[] dstBuf;
    tjDestroy(handle);
}

static void fuzz_tjDecompress(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return;

    unsigned char *dstBuf = nullptr;
    unsigned long jpegSize = static_cast<unsigned long>(Size);

    try {
        if (Size > 0) {
            int width, height, subsamp;
            if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), jpegSize, &width, &height, &subsamp) == 0) {
                int pixelFormat = TJPF_RGB;
                dstBuf = new unsigned char[width * height * tjPixelSize[pixelFormat]];
                if (tjDecompress(handle, const_cast<unsigned char*>(Data), jpegSize, dstBuf, width, 0, height, tjPixelSize[pixelFormat], 0) != 0) {
                    throw std::runtime_error(tjGetErrorStr());
                }
            }
        }
    } catch (const std::exception &e) {
        // Handle exceptions
    }

    delete[] dstBuf;
    tjDestroy(handle);
}

static void fuzz_tjDecompressToYUVPlanes(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) return;

    unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
    unsigned long jpegSize = static_cast<unsigned long>(Size);

    try {
        if (Size > 0) {
            int width, height, subsamp;
            if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), jpegSize, &width, &height, &subsamp) == 0) {
                int strides[3];
                for (int i = 0; i < 3; i++) {
                    int planeSize = tjPlaneSizeYUV(i, width, strides[i], height, subsamp);
                    dstPlanes[i] = new unsigned char[planeSize];
                }
                if (tjDecompressToYUVPlanes(handle, const_cast<unsigned char*>(Data), jpegSize, dstPlanes, width, strides, height, 0) != 0) {
                    throw std::runtime_error(tjGetErrorStr());
                }
            }
        }
    } catch (const std::exception &e) {
        // Handle exceptions
    }

    for (int i = 0; i < 3; i++) {
        delete[] dstPlanes[i];
    }
    tjDestroy(handle);
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    fuzz_tj3DecompressToYUV8(Data, Size);
    fuzz_tjDecompress2(Data, Size);
    fuzz_tjDecompressToYUV(Data, Size);
    fuzz_tjDecompressToYUV2(Data, Size);
    fuzz_tjDecompress(Data, Size);
    fuzz_tjDecompressToYUVPlanes(Data, Size);
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    