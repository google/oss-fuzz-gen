#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract necessary parameters
    if (size < 12) {
        return 0;
    }

    // Initialize the TurboJPEG compressor handle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Extract parameters from the input data
    int width = (int)data[0] + 1;  // Ensure width is at least 1
    int height = (int)data[1] + 1; // Ensure height is at least 1
    int pixelFormat = (int)data[2] % TJ_NUMPF; // Ensure valid pixel format
    int padding = (int)data[3] % 4; // Padding can be 0, 1, 2, or 3

    // Calculate the buffer size for the YUV image
    int yuvSize = tjBufSizeYUV2(width, padding, height, pixelFormat);
    unsigned char *yuvBuffer = (unsigned char *)malloc(yuvSize);
    if (yuvBuffer == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // The input image buffer
    const unsigned char *srcBuffer = data + 4;
    int srcSize = size - 4;

    // Call the function-under-test
    tjEncodeYUV3(handle, srcBuffer, width, padding, height, pixelFormat, yuvBuffer, padding, height, pixelFormat);

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
