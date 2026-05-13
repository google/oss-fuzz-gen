#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Initialize variables for tj3DecodeYUV8 function
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (!handle) {
        return 0; // Return if handle initialization fails
    }

    // Ensure the size is large enough to extract necessary parameters
    if (size < 12) {
        tj3Destroy(handle);
        return 0;
    }

    // Extract parameters from data
    const unsigned char *srcBuf = data;
    int srcSize = static_cast<int>(size);

    // Extract width, height, and pixel format from the input data
    int width = (data[0] << 8) | data[1];
    int height = (data[2] << 8) | data[3];
    int pixelFormat = data[4] % TJ_NUMPF;

    // Validate extracted dimensions and pixel format
    if (width <= 0 || height <= 0 || pixelFormat < 0 || pixelFormat >= TJ_NUMPF) {
        tj3Destroy(handle);
        return 0;
    }

    // Allocate destination buffer (output image buffer)
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (!dstBuf) {
        tj3Destroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tj3DecodeYUV8(handle, srcBuf, srcSize, dstBuf, width, 0, height, pixelFormat);

    // Clean up
    free(dstBuf);
    tj3Destroy(handle);

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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
