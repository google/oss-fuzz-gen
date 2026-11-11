// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tj3YUVPlaneSize at turbojpeg.c:1020:18 in turbojpeg.h
// tj3DecodeYUVPlanes8 at turbojpeg.c:2511:15 in turbojpeg.h
// tjEncodeYUV3 at turbojpeg.c:1734:15 in turbojpeg.h
// tjEncodeYUVPlanes at turbojpeg.c:1663:15 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tj3CompressFromYUVPlanes8 at turbojpeg.c:1259:15 in turbojpeg.h
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

static tjhandle initializeHandle() {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        fprintf(stderr, "Failed to initialize TurboJPEG handle: %s\n", tjGetErrorStr());
    }
    return handle;
}

static void cleanupHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size < 10) return 0; // Ensure there's enough data for basic parameters

    tjhandle handle = initializeHandle();
    if (!handle) return 0;

    const unsigned char *srcPlanes[3];
    int strides[3];
    unsigned char *dstBuf = nullptr;
    int width = Data[0] + 1; // Ensure non-zero width
    int height = Data[1] + 1; // Ensure non-zero height
    int pixelFormat = Data[2] % TJ_NUMPF;
    int pitch = width * tjPixelSize[pixelFormat];

    // Allocate memory for destination buffer
    dstBuf = (unsigned char *)malloc(pitch * height);
    if (!dstBuf) {
        cleanupHandle(handle);
        return 0;
    }

    // Initialize YUV planes
    int subsamp = TJSAMP_444;
    size_t planeSize = tj3YUVPlaneSize(0, width, strides[0], height, subsamp);
    unsigned char *yuvData = (unsigned char *)malloc(planeSize * 3);
    if (!yuvData) {
        free(dstBuf);
        cleanupHandle(handle);
        return 0;
    }
    srcPlanes[0] = yuvData;
    srcPlanes[1] = yuvData + planeSize;
    srcPlanes[2] = yuvData + 2 * planeSize;
    strides[0] = strides[1] = strides[2] = width;

    // Fuzz tj3DecodeYUVPlanes8
    tj3DecodeYUVPlanes8(handle, srcPlanes, strides, dstBuf, width, pitch, height, pixelFormat);

    // Fuzz tjEncodeYUV3
    unsigned char *encodedYUV = (unsigned char *)malloc(planeSize);
    if (encodedYUV) {
        tjEncodeYUV3(handle, dstBuf, width, pitch, height, pixelFormat, encodedYUV, 4, subsamp, 0);
        free(encodedYUV);
    }

    // Fuzz tjEncodeYUVPlanes
    unsigned char *dstPlanes[3];
    dstPlanes[0] = (unsigned char *)malloc(planeSize);
    dstPlanes[1] = (unsigned char *)malloc(planeSize);
    dstPlanes[2] = (unsigned char *)malloc(planeSize);
    if (dstPlanes[0] && dstPlanes[1] && dstPlanes[2]) {
        tjEncodeYUVPlanes(handle, dstBuf, width, pitch, height, pixelFormat, dstPlanes, strides, subsamp, 0);
    }
    free(dstPlanes[0]);
    free(dstPlanes[1]);
    free(dstPlanes[2]);

    // Fuzz tjCompressFromYUVPlanes
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, 75, 0);
    tjFree(jpegBuf);

    // Fuzz tjDecodeYUVPlanes
    tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, dstBuf, width, pitch, height, pixelFormat, 0);

    // Fuzz tj3CompressFromYUVPlanes8
    size_t jpegSize8 = 0;
    unsigned char *jpegBuf8 = nullptr;
    tj3CompressFromYUVPlanes8(handle, srcPlanes, width, strides, height, &jpegBuf8, &jpegSize8);
    tjFree(jpegBuf8);

    free(yuvData);
    free(dstBuf);
    cleanupHandle(handle);

    return 0;
}