#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for YUV buffer
    int width = 128; // Example width
    int height = 128; // Example height
    int yuvSize = tjBufSizeYUV2(width, 4, height, TJSAMP_420);
    unsigned char *yuvBuffer = (unsigned char *)malloc(yuvSize);
    if (yuvBuffer == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Ensure the input data is a valid JPEG image
    unsigned char *nonConstData = const_cast<unsigned char *>(data);
    if (tjDecompressHeader(handle, nonConstData, size, &width, &height) == 0) {
        // Call the function-under-test
        if (tjDecompressToYUV(handle, nonConstData, size, yuvBuffer, 0) != 0) {
            // Handle decompression error if needed
        }
    }

    // Clean up
    free(yuvBuffer);
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
