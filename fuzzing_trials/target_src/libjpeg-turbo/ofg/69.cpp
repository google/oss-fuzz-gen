#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Ensure there is enough data for at least one pixel
    }

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Derive parameters from input data
    int width = data[0] % 256 + 1;  // Ensure width is at least 1
    int height = data[1] % 256 + 1; // Ensure height is at least 1
    int subsamp = data[2] % 5;      // Subsampling value should be within valid range (0 to 4)

    int pitch = width * 3; // Assuming 3 bytes per pixel for RGB

    // Allocate destination buffer
    unsigned long dstSize = tjBufSizeYUV2(width, 1, height, subsamp);
    unsigned char *dstBuf = (unsigned char *)malloc(dstSize);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    int flags = 0; // Example flags, adjust as needed

    // Adjust the input data to ensure it is not null and has a meaningful size
    const unsigned char *srcBuf = data;
    if (size < pitch * height) {
        // If the provided data is not enough, fill the rest with zeroes
        unsigned char *tempBuf = (unsigned char *)malloc(pitch * height);
        if (tempBuf == nullptr) {
            free(dstBuf);
            tjDestroy(handle);
            return 0;
        }
        memcpy(tempBuf, data, size);
        memset(tempBuf + size, 0, pitch * height - size);
        srcBuf = tempBuf;
    }

    // Call the function-under-test
    int result = tj3EncodeYUV8(handle, srcBuf, width, pitch, height, subsamp, dstBuf, flags);
    if (result != 0) {
        // Handle error if needed, for now just clean up
        free(dstBuf);
        if (srcBuf != data) {
            free((void *)srcBuf);
        }
        tjDestroy(handle);
        return 0;
    }

    // Clean up
    free(dstBuf);
    if (srcBuf != data) {
        free((void *)srcBuf);
    }
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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
