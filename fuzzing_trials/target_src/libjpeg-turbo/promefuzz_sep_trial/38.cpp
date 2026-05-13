// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3DecodeYUVPlanes8 at turbojpeg.c:2511:15 in turbojpeg.h
// tjEncodeYUV3 at turbojpeg.c:1734:15 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tj3DecompressToYUVPlanes8 at turbojpeg.c:2125:15 in turbojpeg.h
// tj3CompressFromYUVPlanes8 at turbojpeg.c:1259:15 in turbojpeg.h
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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

static void initializeYUVPlanes(unsigned char **srcPlanes, int width, int height) {
    for (int i = 0; i < 3; i++) {
        srcPlanes[i] = new unsigned char[width * height];
        std::memset(srcPlanes[i], 0, width * height);
    }
}

static void cleanupYUVPlanes(unsigned char **srcPlanes) {
    for (int i = 0; i < 3; i++) {
        delete[] srcPlanes[i];
    }
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    unsigned char *srcPlanes[3];
    initializeYUVPlanes(srcPlanes, 256, 256);

    unsigned char *dstBuf = new unsigned char[256 * 256 * 3];
    int strides[3] = {256, 128, 128};

    try {
        // Fuzz tj3DecodeYUVPlanes8
        tj3DecodeYUVPlanes8(handle, srcPlanes, strides, dstBuf, 256, 256, 256, TJPF_RGB);

        // Fuzz tjEncodeYUV3
        tjEncodeYUV3(handle, dstBuf, 256, 256 * 3, 256, TJPF_RGB, dstBuf, 4, TJSAMP_444, 0);

        // Fuzz tjCompressFromYUVPlanes
        unsigned char *jpegBuf = nullptr;
        unsigned long jpegSize = 0;
        const unsigned char *constSrcPlanes[3] = {srcPlanes[0], srcPlanes[1], srcPlanes[2]};
        tjCompressFromYUVPlanes(handle, constSrcPlanes, 256, strides, 256, TJSAMP_444, &jpegBuf, &jpegSize, 75, 0);
        
        // Fuzz tjDecodeYUVPlanes
        tjDecodeYUVPlanes(handle, constSrcPlanes, strides, TJSAMP_444, dstBuf, 256, 256 * 3, 256, TJPF_RGB, 0);

        // Fuzz tj3DecompressToYUVPlanes8
        unsigned char *dstPlanes[3];
        initializeYUVPlanes(dstPlanes, 256, 256);
        tj3DecompressToYUVPlanes8(handle, Data, Size, dstPlanes, strides);

        // Fuzz tj3CompressFromYUVPlanes8
        size_t jpegSize2 = 0;
        tj3CompressFromYUVPlanes8(handle, constSrcPlanes, 256, strides, 256, &jpegBuf, &jpegSize2);
        
        if (jpegBuf) {
            tjFree(jpegBuf);
        }
        cleanupYUVPlanes(dstPlanes);
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    cleanupYUVPlanes(srcPlanes);
    delete[] dstBuf;
    tjDestroy(handle);

    return 0;
}