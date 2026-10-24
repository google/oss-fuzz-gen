#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Failed to initialize decompressor
    }

    // Dummy values for output parameters
    int width = 100; // Arbitrary non-zero width
    int height = 100; // Arbitrary non-zero height
    int pixelFormat = TJPF_RGB; // Common pixel format
    int flags = 0; // No special flags

    // Allocate a buffer for the decompressed image
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0; // Memory allocation failed
    }

    // Call the function-under-test
    tjDecompress2(handle, data, (unsigned long)size, dstBuf, width, 0, height, pixelFormat, flags);

    // Clean up
    free(dstBuf);
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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
