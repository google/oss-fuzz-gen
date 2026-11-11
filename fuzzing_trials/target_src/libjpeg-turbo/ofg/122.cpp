#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Not enough data to form even a minimal JPEG header
    }

    tjhandle handle = tjInitCompress(); // Initialize a TurboJPEG compressor handle

    if (handle != NULL) {
        int width = 100; // Example width
        int height = 100; // Example height
        int jpegSubsamp = TJSAMP_444; // Example subsampling
        int jpegQual = 75; // Example quality level
        unsigned char *jpegBuf = NULL; // Buffer for the compressed JPEG image
        unsigned long jpegSize = 0; // Size of the JPEG image

        // Use the input data as a dummy image buffer
        // Ensure the buffer is large enough for the example width and height
        if (size >= width * height * 3) {
            // Compress the image
            int result = tjCompress2(handle, data, width, 0, height, TJPF_RGB,
                                     &jpegBuf, &jpegSize, jpegSubsamp, jpegQual, TJFLAG_FASTDCT);

            if (result == 0) {
                // Successfully compressed, do something with jpegBuf if needed
            }

            // Free the JPEG buffer
            tjFree(jpegBuf);
        }

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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
