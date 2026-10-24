// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjGetErrorStr2 at turbojpeg.c:630:17 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjEncodeYUV3 at turbojpeg.c:1734:15 in turbojpeg.h
// tjEncodeYUV2 at turbojpeg.c:1758:15 in turbojpeg.h
// tj3EncodeYUV8 at turbojpeg.c:1688:15 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tj3DecodeYUV8 at turbojpeg.c:2678:15 in turbojpeg.h
// tj3EncodeYUVPlanes8 at turbojpeg.c:1508:15 in turbojpeg.h
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
    tjhandle handle = tjInitCompress();
    if (!handle) {
        fprintf(stderr, "Failed to initialize TurboJPEG: %s\n", tjGetErrorStr2(nullptr));
        exit(1);
    }
    return handle;
}

static void cleanupHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = initializeHandle();

    // Prepare dummy parameters
    int width = 256;
    int height = 256;
    int pitch = 0;
    int pixelFormat = TJPF_RGB;
    int subsamp = TJSAMP_420;
    int flags = 0;
    int align = 4;

    // Allocate buffers
    size_t srcBufSize = width * height * tjPixelSize[pixelFormat];
    unsigned char *srcBuf = (unsigned char *)malloc(srcBufSize);
    unsigned char *dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, align, height, subsamp));

    if (!srcBuf || !dstBuf) {
        fprintf(stderr, "Failed to allocate buffers\n");
        cleanupHandle(handle);
        free(srcBuf);
        free(dstBuf);
        return 0;
    }

    // Fill srcBuf with fuzzer data
    memcpy(srcBuf, Data, Size < srcBufSize ? Size : srcBufSize);

    // Attempt to fuzz tjEncodeYUV3
    tjEncodeYUV3(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, align, subsamp, flags);

    // Attempt to fuzz tjEncodeYUV2
    tjEncodeYUV2(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, subsamp, flags);

    // Attempt to fuzz tj3EncodeYUV8
    tj3EncodeYUV8(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, align);

    // Prepare for tjDecodeYUVPlanes
    const unsigned char *srcPlanes[3] = {dstBuf, nullptr, nullptr};
    int strides[3] = {width, 0, 0};
    unsigned char *decodedBuf = (unsigned char *)malloc(srcBufSize);

    // Attempt to fuzz tjDecodeYUVPlanes
    tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, decodedBuf, width, pitch, height, pixelFormat, flags);

    // Attempt to fuzz tj3DecodeYUV8
    tj3DecodeYUV8(handle, dstBuf, align, decodedBuf, width, pitch, height, pixelFormat);

    // Prepare for tj3EncodeYUVPlanes8
    unsigned char *dstPlanes[3] = {dstBuf, nullptr, nullptr};

    // Attempt to fuzz tj3EncodeYUVPlanes8
    tj3EncodeYUVPlanes8(handle, srcBuf, width, pitch, height, pixelFormat, dstPlanes, strides);

    // Cleanup
    cleanupHandle(handle);
    free(srcBuf);
    free(dstBuf);
    free(decodedBuf);

    return 0;
}