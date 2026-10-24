#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Ensure the input data is large enough to extract necessary parameters
    if (size < 8) {
        tjDestroy(handle);
        return 0;
    }

    // Use the first few bytes of data to define width, height, and pixel format
    int width = data[0] + 1;  // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int pitch = width * 3;    // Assuming 3 bytes per pixel (RGB)
    int pixelFormat = TJPF_RGB;

    // Allocate memory for the source and destination buffers
    unsigned char *srcBuf = (unsigned char *)malloc(width * height * 3);
    if (srcBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }
    unsigned char *dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, pitch, height, TJSAMP_444));
    if (dstBuf == nullptr) {
        free(srcBuf);
        tjDestroy(handle);
        return 0;
    }

    // Copy the input data into the source buffer
    size_t copySize = (size < width * height * 3) ? size : width * height * 3;
    memcpy(srcBuf, data, copySize);

    // Call the function-under-test
    tjEncodeYUV(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, TJSAMP_444, 0);

    // Cleanup
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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
