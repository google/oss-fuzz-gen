#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    if (size < 2 || data == nullptr) {
        return 0;
    }

    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        std::cerr << "Failed to initialize decompressor" << std::endl;
        return 0;
    }

    unsigned char *jpegBuf = (unsigned char *)malloc(size);
    if (jpegBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }
    memcpy(jpegBuf, data, size);

    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;
    int result = tjDecompressHeader3(handle, jpegBuf, (unsigned long)size, &width, &height, &jpegSubsamp, &jpegColorspace);

    if (result == 0 && width > 0 && height > 0) {
        unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[TJPF_RGB]);
        if (dstBuf != nullptr) {
            result = tjDecompress2(handle, jpegBuf, (unsigned long)size, dstBuf, width, 0 /* pitch */, height, TJPF_RGB, TJFLAG_FASTDCT);
            if (result == 0) {
                std::cout << "Decompression successful: " << width << "x" << height << std::endl;
            } else {
                std::cerr << "Decompression failed" << std::endl;
            }
            free(dstBuf);
        }
    } else {
        std::cerr << "Invalid JPEG header or dimensions" << std::endl;
    }

    free(jpegBuf);
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
