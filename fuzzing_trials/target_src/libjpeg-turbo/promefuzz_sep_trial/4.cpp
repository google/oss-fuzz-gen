// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3JPEGBufSize at turbojpeg.c:903:18 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3EncodeYUV8 at turbojpeg.c:1688:15 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3CompressFromYUV8 at turbojpeg.c:1429:15 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
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

static const int TJ_INIT_COMPRESS = 0;
static const int TJ_PARAM_QUALITY = 100;
static const int TJ_PARAM_SUBSAMP = TJSAMP_444;
static const int TJ_PARAM_WIDTH = 800;
static const int TJ_PARAM_HEIGHT = 600;
static const int TJ_PARAM_ALIGN = 4;

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tj3Init(TJ_INIT_COMPRESS);
    if (!handle) return 0;

    if (tj3Set(handle, TJ_PARAM_QUALITY, 75) != 0 ||
        tj3Set(handle, TJ_PARAM_SUBSAMP, TJSAMP_444) != 0 ||
        tj3Set(handle, TJ_PARAM_WIDTH, TJ_PARAM_WIDTH) != 0 ||
        tj3Set(handle, TJ_PARAM_HEIGHT, TJ_PARAM_HEIGHT) != 0 ||
        tj3Set(handle, TJ_PARAM_ALIGN, TJ_PARAM_ALIGN) != 0) {
        tj3Destroy(handle);
        return 0;
    }

    size_t jpegBufSize = tj3JPEGBufSize(TJ_PARAM_WIDTH, TJ_PARAM_HEIGHT, TJSAMP_444);
    unsigned char *jpegBuf = static_cast<unsigned char *>(tj3Alloc(jpegBufSize));
    if (!jpegBuf) {
        tj3Destroy(handle);
        return 0;
    }

    size_t yuvBufSize = tj3YUVBufSize(TJ_PARAM_WIDTH, TJ_PARAM_ALIGN, TJ_PARAM_HEIGHT, TJSAMP_444);
    unsigned char *yuvBuf = static_cast<unsigned char *>(tj3Alloc(yuvBufSize));
    if (!yuvBuf) {
        tj3Free(jpegBuf);
        tj3Destroy(handle);
        return 0;
    }

    if (tj3EncodeYUV8(handle, Data, TJ_PARAM_WIDTH, 0, TJ_PARAM_HEIGHT, TJPF_RGB, yuvBuf, TJ_PARAM_ALIGN) != 0) {
        tj3Free(yuvBuf);
        tj3Free(jpegBuf);
        tj3Destroy(handle);
        return 0;
    }

    size_t jpegSize = jpegBufSize;
    if (tj3CompressFromYUV8(handle, yuvBuf, TJ_PARAM_WIDTH, TJ_PARAM_ALIGN, TJ_PARAM_HEIGHT, &jpegBuf, &jpegSize) != 0) {
        tj3Free(yuvBuf);
        tj3Free(jpegBuf);
        tj3Destroy(handle);
        return 0;
    }

    tj3Free(yuvBuf);
    tj3Free(jpegBuf);
    tj3Destroy(handle);

    return 0;
}