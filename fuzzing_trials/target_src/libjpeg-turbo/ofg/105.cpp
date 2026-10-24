#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    // Alternatively, you can use one of the other paths if needed:
    // #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    // #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    tjhandle handle;
    int width, height, jpegSubsamp, jpegColorspace;
    unsigned char *dstBuf = NULL;
    int pixelFormat = TJPF_RGB; // Choose a pixel format for decompression

    // Initialize the TurboJPEG decompressor
    handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;
    }

    // Decompress the JPEG data
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        // Allocate buffer for the decompressed image
        dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
        if (dstBuf) {
            // Decompress the image
            if (tjDecompress2(handle, data, size, dstBuf, width, 0, height, pixelFormat, 0) == 0) {
                // Successfully decompressed the image, process it if needed
                // For now, we are just demonstrating decompression
            }
            free(dstBuf);
        }
    }

    // Clean up the TurboJPEG decompressor
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

    LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
