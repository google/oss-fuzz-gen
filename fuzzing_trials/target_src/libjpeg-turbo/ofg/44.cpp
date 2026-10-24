#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Exit if input size is too small
    }

    // Initialize TurboJPEG decompressor
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0; // Exit if decompressor initialization fails
    }

    // Attempt to decompress the input data
    int width, height, jpegSubsamp, jpegColorspace;
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        // Allocate memory for the decompressed image
        unsigned long jpegSize = tjBufSize(width, height, jpegSubsamp);
        unsigned char *jpegBuf = (unsigned char *)malloc(jpegSize);
        if (jpegBuf != NULL) {
            // Decompress the image
            tjDecompress2(handle, data, size, jpegBuf, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);

            // Free the allocated memory
            free(jpegBuf);
        }
    }

    // Clean up the TurboJPEG decompressor
    tjDestroy(handle);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
