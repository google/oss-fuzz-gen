#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to determine width and height
    }

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0; // Failed to initialize
    }

    // Extract width and height from the input data
    int width = data[0] + 1;  // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int pixelFormat = TJPF_RGB; // Assume RGB format for simplicity
    int quality = 75; // Default quality

    // Calculate the number of pixels and check if size is sufficient
    int pixelSize = tjPixelSize[pixelFormat];
    int requiredSize = width * height * pixelSize;
    if (size < requiredSize + 4) {
        tjDestroy(handle);
        return 0; // Not enough data for the image
    }

    // Set up the destination buffer for compressed data
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    // Call tjCompress2
    int result = tjCompress2(
        handle,
        data + 4, // Skip the first 4 bytes used for width and height
        width,
        0, // pitch (0 means use width * pixelSize)
        height,
        pixelFormat,
        &jpegBuf,
        &jpegSize,
        TJSAMP_444, // Subsampling option
        quality,
        TJFLAG_FASTDCT // Use fast DCT
    );

    // Free the JPEG buffer
    if (jpegBuf != nullptr) {
        tjFree(jpegBuf);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
