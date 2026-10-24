#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    tjhandle handle = tjInitCompress();  // Initialize a TurboJPEG compressor

    if (handle != nullptr) {
        // Prepare a simple RGB image buffer from the input data
        int width = 100; // Example width
        int height = 100; // Example height
        int pixelFormat = TJPF_RGB;
        int pitch = width * tjPixelSize[pixelFormat];
        unsigned char *jpegBuf = nullptr;
        unsigned long jpegSize = 0;

        // Ensure the input data is large enough for an image buffer
        if (size >= (size_t)(pitch * height)) {
            // Compress the image
            int result = tjCompress2(handle, data, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize, TJSAMP_444, 100, TJFLAG_FASTDCT);

            if (result == 0) {
                // Successfully compressed the image, do something with jpegBuf if needed
            }

            // Free the JPEG buffer
            tjFree(jpegBuf);
        }

        // Destroy the TurboJPEG handle
        tjDestroy(handle);
    }

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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
