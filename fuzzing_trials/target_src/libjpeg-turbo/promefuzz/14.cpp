// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjEncodeYUV3 at turbojpeg.c:1734:15 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjEncodeYUVPlanes at turbojpeg.c:1663:15 in turbojpeg.h
// tjCompressFromYUV at turbojpeg.c:1476:15 in turbojpeg.h
// tjCompress2 at turbojpeg.c:1204:15 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
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
#include <cstdlib>
#include <cstring>
#include <iostream>

static tjhandle createHandle() {
    return tjInitCompress();
}

static void destroyHandle(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = createHandle();
    if (!handle) return 0;

    // Define some parameters for the functions
    int width = 256;
    int height = 256;
    int pitch = width * 3;
    int pixelFormat = TJPF_RGB;
    int subsamp = TJSAMP_420;
    int flags = 0;
    int align = 1;
    int jpegQual = 75;

    // Buffers
    size_t srcBufSize = width * height * 3;
    unsigned char *srcBuf = (unsigned char *)malloc(srcBufSize);
    size_t dstBufSize = tjBufSizeYUV2(width, align, height, subsamp);
    unsigned char *dstBuf = (unsigned char *)malloc(dstBufSize);
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    if (srcBuf && dstBuf) {
        // Fill source buffer with fuzz data
        size_t copySize = std::min(Size, srcBufSize);
        memcpy(srcBuf, Data, copySize);

        // Call tjEncodeYUV3
        tjEncodeYUV3(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, align, subsamp, flags);

        // Call tjCompress
        tjCompress(handle, srcBuf, width, pitch, height, 3, dstBuf, &jpegSize, subsamp, jpegQual, flags);

        // Call tjEncodeYUVPlanes
        unsigned char *dstPlanes[3] = {
            dstBuf,
            dstBuf + tjPlaneSizeYUV(1, width, align, height, subsamp),
            dstBuf + tjPlaneSizeYUV(1, width, align, height, subsamp) * 2
        };
        int strides[3] = {
            static_cast<int>(tjPlaneSizeYUV(0, width, align, height, subsamp) / height),
            static_cast<int>(tjPlaneSizeYUV(1, width, align, height, subsamp) / (height / 2)),
            static_cast<int>(tjPlaneSizeYUV(2, width, align, height, subsamp) / (height / 2))
        };
        tjEncodeYUVPlanes(handle, srcBuf, width, pitch, height, pixelFormat, dstPlanes, strides, subsamp, flags);

        // Call tjCompressFromYUV
        tjCompressFromYUV(handle, dstBuf, width, align, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);

        // Call tjCompress2
        tjCompress2(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize, subsamp, jpegQual, flags);

        // Call tjCompressFromYUVPlanes
        const unsigned char *srcPlanes[3] = {
            dstBuf,
            dstBuf + tjPlaneSizeYUV(1, width, align, height, subsamp),
            dstBuf + tjPlaneSizeYUV(1, width, align, height, subsamp) * 2
        };
        tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);
    }

    // Cleanup
    free(srcBuf);
    free(dstBuf);
    if (jpegBuf) tjFree(jpegBuf);
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    