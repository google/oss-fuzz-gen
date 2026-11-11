#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize TurboJPEG decompressor
    tjhandle decompressor = tjInitDecompress();
    if (decompressor == nullptr) {
        return 0;
    }

    // Set up parameters for tjDecompress2
    unsigned long jpegSize = static_cast<unsigned long>(size);
    int width = 100;  // Arbitrary non-zero width
    int height = 100; // Arbitrary non-zero height
    int pixelFormat = TJPF_RGB;  // Common pixel format
    int pitch = 0; // Auto-calculate pitch
    int flags = 0; // No flags

    // Allocate buffer for decompressed image
    unsigned char* destBuffer = static_cast<unsigned char*>(malloc(width * height * tjPixelSize[pixelFormat]));
    if (destBuffer == nullptr) {
        tjDestroy(decompressor);
        return 0;
    }

    // Call the function-under-test
    tjDecompress2(decompressor, data, jpegSize, destBuffer, width, pitch, height, pixelFormat, flags);

    // Clean up
    free(destBuffer);
    tjDestroy(decompressor);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
