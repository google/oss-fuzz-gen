#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    if (size < 4) return 0; // Ensure we have enough data

    tjhandle handle = tjInitCompress();
    if (!handle) return 0;

    // Extract some parameters from the input data
    int width = data[0] + 1;  // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int pixelFormat = data[2] % TJ_NUMPF; // Valid pixel format
    int padding = data[3] % 4; // Valid padding (0, 1, 2, 3)

    // Calculate the required buffer size for YUV image
    int yuvSize = tjBufSizeYUV2(width, padding, height, TJ_420);

    // Allocate memory for the YUV image
    unsigned char *yuvBuffer = (unsigned char *)malloc(yuvSize);
    if (!yuvBuffer) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tjEncodeYUV3(handle, data, width, padding, height, pixelFormat, yuvBuffer, padding, TJ_420, 0);

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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
