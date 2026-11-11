#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to be a valid JPEG
    }

    // Initialize TurboJPEG decompressor
    tjhandle tjInstance = tjInitDecompress();
    if (tjInstance == nullptr) {
        return 0; // Failed to initialize
    }

    // Variables to hold image properties
    int width, height, jpegSubsamp, jpegColorspace;

    // Attempt to read the header of the JPEG image
    if (tjDecompressHeader3(tjInstance, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        // Allocate buffer for decompressed image
        unsigned char *imgBuf = (unsigned char *)malloc(width * height * tjPixelSize[TJPF_RGB]);
        if (imgBuf != nullptr) {
            // Decompress the image
            if (tjDecompress2(tjInstance, data, size, imgBuf, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT) == 0) {
                // Successfully decompressed, simulate usage
                // Here we can perform operations on imgBuf if needed
            }
            free(imgBuf);
        }
    }

    // Clean up
    tjDestroy(tjInstance);
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

    LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
