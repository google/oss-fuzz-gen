#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Initialize the TurboJPEG decompressor
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    int width, height, jpegSubsamp, jpegColorspace;
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) != 0) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the destination buffer
    unsigned long dstSize = width * height * tjPixelSize[TJPF_RGB]; // Adjust size based on image dimensions
    unsigned char *dstBuf = (unsigned char *)malloc(dstSize);
    if (!dstBuf) {
        tjDestroy(handle);
        return 0;
    }

    // Decompress the JPEG image
    int result = tjDecompress2(handle, data, size, dstBuf, width, 0, height, TJPF_RGB, 0);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return result;
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
