#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    // Define parameters for tj3DecodeYUVPlanes8
    const unsigned char *yuvPlanes[3];
    int strides[3];
    unsigned char *dstBuf;
    int width = 16;  // Example width
    int height = 16; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int flags = 0; // Example flags

    // Ensure the input data is large enough to fill the YUV planes
    if (size < width * height * 3 / 2) {
        tjDestroy(handle);
        return 0;
    }

    // Assign the YUV planes
    yuvPlanes[0] = data; // Y plane
    yuvPlanes[1] = data + width * height; // U plane
    yuvPlanes[2] = data + width * height * 5 / 4; // V plane

    // Set strides for each plane
    strides[0] = width;
    strides[1] = width / 2;
    strides[2] = width / 2;

    // Allocate memory for the destination buffer
    dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (!dstBuf) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    if (tj3DecodeYUVPlanes8(handle, yuvPlanes, strides, dstBuf, width, 0, height, pixelFormat) != 0) {
        // Handle error
        free(dstBuf);
        tjDestroy(handle);
        return 0;
    }

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
