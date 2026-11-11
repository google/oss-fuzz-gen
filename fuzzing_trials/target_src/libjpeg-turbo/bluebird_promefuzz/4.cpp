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
#include <fstream>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // 1. Test TJBUFSIZE
    if (Size >= 8) {
        int width = static_cast<int>(Data[0]) | (static_cast<int>(Data[1]) << 8);
        int height = static_cast<int>(Data[2]) | (static_cast<int>(Data[3]) << 8);
        if (width > 0 && height > 0) {
            unsigned long bufSize = TJBUFSIZE(width, height);
            std::cout << "Buffer size for (" << width << ", " << height << "): " << bufSize << std::endl;
        }
    }

    // 2. Test tjDecompressHeader3
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    int width, height, jpegSubsamp, jpegColorspace;
    if (tjDecompressHeader3(handle, Data, Size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        std::cout << "Decompress Header: " << width << "x" << height << ", subsamp: " << jpegSubsamp
                  << ", colorspace: " << jpegColorspace << std::endl;
    }

    // 3. Test tjDecompress2
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[TJPF_RGB]);
    if (dstBuf) {
        if (tjDecompress2(handle, Data, Size, dstBuf, width, 0, height, TJPF_RGB, 0) == 0) {
            std::cout << "Decompressed image to buffer" << std::endl;
        }
        free(dstBuf);
    }

    // 4. Test tjCompress2
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    if (tjCompress2(handle, Data, width, 0, height, TJPF_RGB, &jpegBuf, &jpegSize, TJSAMP_444, 75, 0) == 0) {
        std::cout << "Compressed image size: " << jpegSize << std::endl;
        tjFree(jpegBuf);
    }

    // 5. Test tjCompressFromYUVPlanes
    const unsigned char *srcPlanes[3] = {Data, Data + width * height, Data + 2 * width * height};
    int strides[3] = {width, width / 2, width / 2};
    jpegBuf = nullptr;
    jpegSize = 0;
    if (tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, TJSAMP_420, &jpegBuf, &jpegSize, 75, 0) == 0) {
        std::cout << "Compressed YUV planes to JPEG size: " << jpegSize << std::endl;
        tjFree(jpegBuf);
    }

    // 6. Test tj3JPEGBufSize
    if (Size >= 12) {
        int subsamp = static_cast<int>(Data[4]);
        size_t maxBufSize = tj3JPEGBufSize(width, height, subsamp);

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tj3JPEGBufSize to TJBUFSIZEYUV
        unsigned long ret_TJBUFSIZEYUV_xxhuv = TJBUFSIZEYUV((int )maxBufSize, (int )maxBufSize, (int )jpegSize);
        if (ret_TJBUFSIZEYUV_xxhuv < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        std::cout << "Max JPEG buffer size for (" << width << ", " << height << "): " << maxBufSize << std::endl;
    }

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
