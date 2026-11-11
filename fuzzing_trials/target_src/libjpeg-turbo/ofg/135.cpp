#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    unsigned char *yuvBuffer = nullptr;
    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;

    // Attempt to get header information from the JPEG data
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        // Allocate buffer for YUV image
        yuvBuffer = (unsigned char *)malloc(tjBufSizeYUV2(width, 4, height, jpegSubsamp));
        if (yuvBuffer) {
            // Call the function-under-test
            tjDecompressToYUV2(handle, data, size, yuvBuffer, width, 4, height, 0);

            // Free the YUV buffer
            free(yuvBuffer);
        }
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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
