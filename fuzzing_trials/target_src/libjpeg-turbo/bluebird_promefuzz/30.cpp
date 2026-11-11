#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../src/turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    int width = 0, height = 0, jpegSubsamp = 0;

    // Fuzz tjDecompressHeader2
    tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &jpegSubsamp);

    // Allocate buffers for tjCompress and tjDecompress2
    unsigned char* srcBuf = (unsigned char*)malloc(width * height * 3);
    unsigned char* dstBuf = (unsigned char*)malloc(width * height * 3);
    unsigned long compressedSize = 0;

    if (srcBuf && dstBuf) {
        // Fuzz tjCompress
        tjCompress(handle, srcBuf, width, 0, height, 3, dstBuf, &compressedSize, jpegSubsamp, 75, 0);

        // Fuzz tjDecompress2
        tjDecompress2(handle, Data, Size, dstBuf, width, 0, height, TJPF_RGB, 0);
    }

    // Fuzz tjTransform
    tjtransform transform;
    memset(&transform, 0, sizeof(transform));
    unsigned char* dstBufs[1] = { nullptr };
    unsigned long dstSizes[1] = { 0 };
    tjTransform(handle, Data, Size, 1, dstBufs, dstSizes, &transform, 0);

    // Fuzz tjDecompressToYUV2
    unsigned char* yuvBuf = (unsigned char*)malloc(width * height * 3 / 2); // YUV buffer size
    if (yuvBuf) {
        tjDecompressToYUV2(handle, Data, Size, yuvBuf, width, 4, height, 0);
        free(yuvBuf);
    }

    // Fuzz tj3GetErrorCode
    tj3GetErrorCode(handle);

    // Cleanup
    if (srcBuf) free(srcBuf);
    if (dstBuf) free(dstBuf);
    if (dstBufs[0]) tjFree(dstBufs[0]);
    tjDestroy(handle);

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
