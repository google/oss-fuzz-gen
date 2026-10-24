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

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    if (size < 10) {
        // Ensure there's enough data for the minimum required parameters
        return 0;
    }

    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Initialize parameters for tjDecodeYUV
    const unsigned char *srcBuf = data;
    int pad = 1;  // Assuming some padding
    int subsamp = TJSAMP_444;  // Assuming a subsampling type
    int dstWidth = 10;  // Minimum width
    int dstHeight = 10;  // Minimum height
    int pitch = dstWidth * tjPixelSize[TJPF_RGB];  // Assuming RGB pixel format
    int pixelFormat = TJPF_RGB;  // Assuming RGB pixel format

    // Ensure the source buffer is large enough for the YUV image
    int minSrcSize = tjBufSizeYUV2(dstWidth, pad, dstHeight, subsamp);
    if (size < minSrcSize) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the destination buffer
    unsigned char *dstBuf = (unsigned char *)malloc(dstWidth * dstHeight * tjPixelSize[pixelFormat]);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tjDecodeYUV(handle, srcBuf, pad, subsamp, dstBuf, dstWidth, pitch, dstHeight, pixelFormat, 0);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
