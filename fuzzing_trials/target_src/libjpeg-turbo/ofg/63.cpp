#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If handle initialization fails, exit early
    }

    // Allocate memory for the decompressed image
    int width = 800;  // Example width
    int height = 600; // Example height
    int pixelFormat = TJPF_RGB; // RGB format for decompressed image
    int pitch = width * tjPixelSize[pixelFormat];
    unsigned char *dstBuffer = (unsigned char *)malloc(pitch * height);

    if (dstBuffer == nullptr) {
        tjDestroy(handle);
        return 0; // If memory allocation fails, exit early
    }

    // Call the function-under-test
    int result = tjDecompress(handle, (unsigned char *)data, (unsigned long)size, dstBuffer, width, pitch, height, pixelFormat, 0);

    // Clean up
    free(dstBuffer);
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
