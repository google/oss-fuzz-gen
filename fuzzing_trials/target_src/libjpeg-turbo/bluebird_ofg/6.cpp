#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Initialize variables for tjDecompressToYUV2
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    unsigned char *jpegBuf = const_cast<unsigned char *>(data);
    unsigned long jpegSize = static_cast<unsigned long>(size);

    // Assuming some default width, height, and subsampling for the YUV image
    int width = 128;  // Default width
    int height = 128; // Default height
    int subsamp = TJSAMP_420; // Default subsampling
    int flags = 0; // Default flags
    int align = 1; // Default alignment

    // Calculate the buffer size needed for the YUV image
    int yuvSize = tjBufSizeYUV2(width, align, height, subsamp);
    unsigned char *yuvBuf = static_cast<unsigned char *>(malloc(yuvSize));
    if (yuvBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 7 of tjDecompressToYUV2
    tjDecompressToYUV2(handle, jpegBuf, jpegSize, yuvBuf, width, align, height, -1);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Clean up
    free(yuvBuf);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
