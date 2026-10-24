#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Ensure the size is not zero to allocate memory
    if (size == 0) return 0;

    // Initialize TurboJPEG decompressor
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Initialization failed
    }

    int width, height, jpegSubsamp, jpegColorspace;
    // Attempt to read the JPEG header
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        // Allocate buffer for decompressed image
        unsigned long bufferSize = tjBufSizeYUV2(width, 4, height, jpegSubsamp);
        unsigned char *buffer = static_cast<unsigned char *>(malloc(bufferSize));
        if (buffer != nullptr) {
            // Attempt to decompress the image
            tjDecompress2(handle, data, size, buffer, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);
            free(buffer); // Free the buffer after use
        }
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
