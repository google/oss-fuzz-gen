#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    if (size < 12) {
        // Not enough data to extract the required parameters
        return 0;
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Extract parameters from data
    int width = (int)data[0] + 1;  // Ensure width is at least 1
    int height = (int)data[1] + 1; // Ensure height is at least 1
    int strides = (int)data[2] + 1; // Ensure strides is at least 1
    int subsamp = (int)(data[3] % 4); // Valid subsampling values are 0, 1, 2, 3
    int flags = (int)(data[4] % 2); // Flags can be 0 or 1

    // Prepare YUV image buffer
    const unsigned char *yuvImage = data + 5;
    int yuvSize = size - 5;

    // Calculate the minimum required YUV buffer size
    int minYUVSize = tjBufSizeYUV2(width, strides, height, subsamp);
    if (yuvSize < minYUVSize) {
        tjDestroy(handle);
        return 0;
    }

    // Prepare output buffer
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    // Call the function-under-test
    tjCompressFromYUV(handle, yuvImage, width, strides, height, subsamp, &jpegBuf, &jpegSize, 100, flags);

    // Clean up
    tjFree(jpegBuf);
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
