// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjGetErrorStr at turbojpeg.c:636:17 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjDecodeYUV at turbojpeg.c:2724:15 in turbojpeg.h
// tjEncodeYUV2 at turbojpeg.c:1758:15 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tjEncodeYUV at turbojpeg.c:1767:15 in turbojpeg.h
// tj3DecodeYUV8 at turbojpeg.c:2678:15 in turbojpeg.h
// tj3YUVPlaneWidth at turbojpeg.c:1057:15 in turbojpeg.h
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

static tjhandle createHandle() {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        std::cerr << "Failed to initialize TurboJPEG handle: " << tjGetErrorStr() << std::endl;
    }
    return handle;
}

static void destroyHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = createHandle();
    if (!handle) return 0;

    const unsigned char *srcBuf = Data;
    int width = 100, height = 100, pitch = width * 3;
    int align = 1, subsamp = TJSAMP_444, pixelFormat = TJPF_RGB, flags = 0;

    // Ensure srcBuf is large enough for the operations
    size_t minSrcBufSize = tjBufSizeYUV2(width, align, height, subsamp);
    if (Size < minSrcBufSize) {
        destroyHandle(handle);
        return 0;
    }

    unsigned char *dstBuf = (unsigned char *)malloc(pitch * height);
    if (!dstBuf) {
        destroyHandle(handle);
        return 0;
    }

    // Fuzz tjDecodeYUV
    tjDecodeYUV(handle, srcBuf, align, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);

    // Fuzz tjEncodeYUV2
    tjEncodeYUV2(handle, dstBuf, width, pitch, height, pixelFormat, dstBuf, subsamp, flags);

    // Fuzz tjDecodeYUVPlanes
    const unsigned char *srcPlanes[3] = { srcBuf, srcBuf, srcBuf };
    int strides[3] = { pitch, pitch / 2, pitch / 2 };
    tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);

    // Fuzz tjEncodeYUV
    tjEncodeYUV(handle, dstBuf, width, pitch, height, 3, dstBuf, subsamp, flags);

    // Fuzz tj3DecodeYUV8
    tj3DecodeYUV8(handle, srcBuf, align, dstBuf, width, pitch, height, pixelFormat);

    // Fuzz tj3YUVPlaneWidth
    for (int componentID = 0; componentID < 3; ++componentID) {
        tj3YUVPlaneWidth(componentID, width, subsamp);
    }

    free(dstBuf);
    destroyHandle(handle);
    return 0;
}