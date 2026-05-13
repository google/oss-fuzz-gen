#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Initialize the TurboJPEG compressor
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) return 0;

    // Define parameters for tjCompressFromYUV
    int width = 16;  // Example width
    int height = 16; // Example height
    int subsamp = TJSAMP_444; // Example subsampling
    int padding = 1; // Example padding
    int flags = 0;   // Example flags

    // Ensure the input data is large enough for YUV image
    int yuvSize = tjBufSizeYUV2(width, padding, height, subsamp);
    if (size < (size_t)yuvSize) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the compressed image
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    // Call the function-under-test
    tjCompressFromYUV(handle, data, width, padding, height, subsamp, &jpegBuf, &jpegSize, 100, flags);

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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
