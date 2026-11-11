#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Define and initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Ensure the input data is large enough to avoid accessing out of bounds
    if (size < 6) {
        tjDestroy(handle);
        return 0;
    }

    // Extract width and height from the input data
    int width = data[0] + 1;  // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1

    // Calculate the size of the image buffer
    int pixelFormat = TJPF_RGB;
    int pitch = width * tjPixelSize[pixelFormat];
    size_t imageSize = pitch * height;

    // Allocate memory for the image buffer
    unsigned char *srcBuf = (unsigned char *)malloc(imageSize);
    if (srcBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Fill the source buffer with data from the input
    size_t copySize = (size - 2 < imageSize) ? size - 2 : imageSize;
    memcpy(srcBuf, data + 2, copySize);

    // Allocate memory for the destination buffer
    int subsamp = data[2] % 4; // Ensure subsampling is a valid value
    unsigned char *dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, pitch, height, subsamp));
    if (dstBuf == nullptr) {
        free(srcBuf);
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tjEncodeYUV2(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, subsamp, 0);

    // Clean up
    free(srcBuf);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
