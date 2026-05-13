#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == NULL) {
        return 0; // Failed to initialize, nothing to test
    }

    // Set up some dummy parameters for compression
    int width = 100;
    int height = 100;
    int jpegSubsamp = TJSAMP_444;
    int jpegQual = 75;
    unsigned char *jpegBuf = NULL;
    size_t jpegSize = 0; // Corrected type from unsigned long to size_t

    // Allocate a buffer for the image data
    unsigned char *imgBuf = (unsigned char *)malloc(width * height * 3);
    if (imgBuf == NULL) {
        tj3Destroy(handle);
        return 0; // Failed to allocate memory
    }

    // Copy the input data into the image buffer
    memcpy(imgBuf, data, size < (width * height * 3) ? size : (width * height * 3));

    // Attempt to compress the image
    if (tj3Compress8(handle, imgBuf, width, 0, height, TJPF_RGB, &jpegBuf, &jpegSize) < 0) {
        // Handle compression error
    }

    // Clean up
    tj3Destroy(handle);
    free(imgBuf);
    if (jpegBuf != NULL) {
        tj3Free(jpegBuf);
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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
