#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>  // For close() and write()

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Declare and initialize necessary variables
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Check if the input size is sufficient for a minimal JPEG header
    if (size < 2 || data[0] != 0xFF || data[1] != 0xD8) {
        tjDestroy(handle);
        return 0;
    }

    // Initialize the parameters for tj3LoadImage16
    int width = 0;
    int pitch = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB;

    // Correct the function call to match the expected parameters
    unsigned short *image = tj3LoadImage16(handle, reinterpret_cast<const char*>(data), &width, pitch, &height, &pixelFormat);

    // Clean up
    if (image != nullptr) {
        tj3Free(image);  // Corrected function call for freeing unsigned short*
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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
