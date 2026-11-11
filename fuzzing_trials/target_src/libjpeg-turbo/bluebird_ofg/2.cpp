#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;
    }

    // Create a buffer for the decompressed image
    int width = 128;  // Example width
    int height = 128; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int pitch = width * tjPixelSize[pixelFormat];
    unsigned char *dest = (unsigned char *)malloc(pitch * height);
    if (dest == NULL) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    if (tjDecompress2(handle, data, size, dest, width, pitch, height, pixelFormat, 0) == -1) {
        free(dest);
        tjDestroy(handle);
        return 0;
    }

    // Clean up
    free(dest);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
