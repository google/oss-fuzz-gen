// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjDecodeYUV at turbojpeg.c:2724:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
// tjDecodeYUVPlanes at turbojpeg.c:2652:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjAlloc at turbojpeg.c:883:26 in turbojpeg.h
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
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Minimum size check for width, height, subsamp

    // Test tjBufSizeYUV
    int width = Data[0];
    int height = Data[1];
    int subsamp = Data[2];
    unsigned long yuvSize = tjBufSizeYUV(width, height, subsamp);

    // Test tjDecompressHeader2
    tjhandle handle = tjInitDecompress();
    if (handle) {
        int jpegWidth = 0, jpegHeight = 0, jpegSubsamp = 0;
        tjDecompressHeader2(handle, const_cast<unsigned char *>(Data), Size, &jpegWidth, &jpegHeight, &jpegSubsamp);
        tjDestroy(handle);
    }

    // Test tjCompress
    handle = tjInitCompress();
    if (handle) {
        unsigned char *srcBuf = tjAlloc(width * height * 3); // Assuming 3 bytes per pixel for RGB
        unsigned char *dstBuf = nullptr;
        unsigned long compressedSize = 0;
        if (srcBuf) {
            memcpy(srcBuf, Data, std::min(Size, static_cast<size_t>(width * height * 3)));
            tjCompress(handle, srcBuf, width, 0, height, 3, dstBuf, &compressedSize, subsamp, 75, 0);
            tjFree(srcBuf);
        }
        tjDestroy(handle);
    }

    // Test tjDecodeYUV
    handle = tjInitDecompress();
    if (handle) {
        unsigned char *dstBuf = tjAlloc(width * height * 3); // Assuming 3 bytes per pixel for RGB
        if (dstBuf && Size >= yuvSize) { // Ensure input data is large enough
            tjDecodeYUV(handle, Data, 1, subsamp, dstBuf, width, 0, height, TJPF_RGB, 0);
            tjFree(dstBuf);
        } else {
            tjFree(dstBuf);
        }
        tjDestroy(handle);
    }

    // Test tjDecodeYUVPlanes
    handle = tjInitDecompress();
    if (handle) {
        unsigned char *dstBuf = tjAlloc(width * height * 3); // Assuming 3 bytes per pixel for RGB
        if (dstBuf && Size >= yuvSize) { // Ensure input data is large enough
            const unsigned char *srcPlanes[3] = {Data, Data + 1, Data + 2};
            int strides[3] = {width, width / 2, width / 2};
            tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, dstBuf, width, 0, height, TJPF_RGB, 0);
            tjFree(dstBuf);
        } else {
            tjFree(dstBuf);
        }
        tjDestroy(handle);
    }

    // Test tjAlloc
    unsigned char *allocBuf = tjAlloc(Size);
    if (allocBuf) {
        memcpy(allocBuf, Data, Size);
        tjFree(allocBuf);
    }

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    