#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0; // Not enough data to proceed
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0; // Failed to initialize
    }

    // Define YUV planes
    const unsigned char *yuvPlanes[3];
    int strides[3];
    int width, height;

    // Extract width and height from data
    width = (data[0] << 8) | data[1];
    height = (data[2] << 8) | data[3];

    // Ensure width and height are positive and reasonable
    if (width <= 0 || height <= 0 || width > 65535 || height > 65535) {
        tj3Destroy(handle);
        return 0;
    }

    // Calculate strides and set YUV planes
    strides[0] = width;
    strides[1] = strides[2] = width / 2;

    size_t ySize = width * height;
    size_t uvSize = (width / 2) * (height / 2);

    if (size < 4 + ySize + 2 * uvSize) {
        tj3Destroy(handle);
        return 0; // Not enough data for YUV planes
    }

    yuvPlanes[0] = data + 4;
    yuvPlanes[1] = data + 4 + ySize;
    yuvPlanes[2] = data + 4 + ySize + uvSize;

    // Allocate memory for compressed image
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Call the function-under-test
    int result = tj3CompressFromYUVPlanes8(handle, yuvPlanes, width, strides, height, &jpegBuf, &jpegSize);

    // Clean up
    tj3Destroy(handle);
    tj3Free(jpegBuf);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
