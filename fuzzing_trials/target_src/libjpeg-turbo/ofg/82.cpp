#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Initialize a TurboJPEG decompressor handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) return 0;

    // Allocate memory for the output buffer
    int width = 64;  // Example width
    int height = 64; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int outputBufferSize = width * height * tjPixelSize[pixelFormat];
    unsigned char *outputBuffer = (unsigned char *)malloc(outputBufferSize);
    if (outputBuffer == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tj3DecodeYUV8(
        handle,
        data, // Input YUV buffer
        size, // Size of the input buffer
        outputBuffer, // Output buffer for the decoded image
        width, // Width of the image
        4, // Example pitch (bytes per row in the output buffer)
        height, // Height of the image
        pixelFormat // Pixel format
    );

    // Clean up
    free(outputBuffer);
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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
