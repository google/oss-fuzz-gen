// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjEncodeYUV3 at turbojpeg.c:1734:15 in turbojpeg.h
// tjCompress2 at turbojpeg.c:1204:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tj3CompressFromYUV8 at turbojpeg.c:1429:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjCompressFromYUV at turbojpeg.c:1476:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
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
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static tjhandle createHandle() {
    return tjInitCompress();
}

static void destroyHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = createHandle();
    if (!handle) return 0;

    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    unsigned char *srcBuf = const_cast<unsigned char*>(Data);

    int width = 100;
    int height = 100;
    int pixelFormat = TJPF_RGB;
    int subsamp = TJSAMP_420;
    int jpegQual = 75;
    int flags = 0;
    int pitch = width * tjPixelSize[pixelFormat];
    int align = 4;

    // Ensure the source buffer is large enough
    if (Size < static_cast<size_t>(pitch * height)) {
        destroyHandle(handle);
        return 0;
    }

    // Fuzz tjEncodeYUV3
    unsigned char *yuvBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, align, height, subsamp));
    if (yuvBuf) {
        tjEncodeYUV3(handle, srcBuf, width, pitch, height, pixelFormat, yuvBuf, align, subsamp, flags);
        free(yuvBuf);
    }

    // Fuzz tjCompress2
    tjCompress2(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize, subsamp, jpegQual, flags);
    tjFree(jpegBuf);

    // Fuzz tj3CompressFromYUV8
    size_t jpegSize_t = 0;
    tj3CompressFromYUV8(handle, srcBuf, width, align, height, &jpegBuf, &jpegSize_t);
    tjFree(jpegBuf);

    // Fuzz tjCompressFromYUVPlanes
    const unsigned char *srcPlanes[3] = { srcBuf, srcBuf, srcBuf };
    int strides[3] = { pitch, pitch, pitch };
    tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);
    tjFree(jpegBuf);

    // Fuzz tjCompress
    jpegSize = tjBufSize(width, height, subsamp);
    unsigned char *dstBuf = (unsigned char *)malloc(jpegSize);
    if (dstBuf) {
        tjCompress(handle, srcBuf, width, pitch, height, tjPixelSize[pixelFormat], dstBuf, &jpegSize, subsamp, jpegQual, flags);
        free(dstBuf);
    }

    // Fuzz tjCompressFromYUV
    tjCompressFromYUV(handle, srcBuf, width, align, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);
    tjFree(jpegBuf);

    destroyHandle(handle);
    return 0;
}