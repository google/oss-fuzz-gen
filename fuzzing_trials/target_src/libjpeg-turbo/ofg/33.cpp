#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Ensure there is enough data to read width and height
    }

    // Initialize the TurboJPEG compressor
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0; // Initialization failed
    }

    // Define and initialize parameters for tjCompress
    int width = (int)data[0] + 1;  // Ensure width is at least 1
    int height = (int)data[1] + 1; // Ensure height is at least 1
    int pixelFormat = TJPF_RGB;    // Using RGB pixel format
    int quality = 75;              // Set a default quality value
    int subsamp = TJSAMP_444;      // Use 4:4:4 subsampling

    unsigned char *compressedBuffer = nullptr;
    unsigned long compressedSize = 0;

    // Allocate memory for the compressed buffer
    compressedBuffer = (unsigned char *)malloc(tjBufSize(width, height, subsamp));
    if (compressedBuffer == nullptr) {
        tjDestroy(handle);
        return 0; // Memory allocation failed
    }

    // Call the function-under-test
    int result = tjCompress(handle, (unsigned char *)data, width, 0, height, pixelFormat, compressedBuffer, &compressedSize, subsamp, quality, TJFLAG_FASTDCT);

    // Clean up
    if (compressedBuffer != nullptr) {
        tjFree(compressedBuffer);
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
