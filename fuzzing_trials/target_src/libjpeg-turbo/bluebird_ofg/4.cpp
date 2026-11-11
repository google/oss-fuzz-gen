#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for tj3JPEGBufSize
    if (size < 3) {
        return 0; // Not enough data to process
    }

    int width = data[0] + 1;  // Ensure minimum valid width
    int height = data[1] + 1; // Ensure minimum valid height
    int jpegSubsamp = data[2] % 5; // Valid subsampling options are 0-4

    // Calculate the buffer size for the input image
    int pixelFormat = TJPF_RGB;
    size_t inputBufferSize = width * height * tjPixelSize[pixelFormat];

    // Ensure the provided data has enough bytes for the input image
    if (size < inputBufferSize + 3) {
        return 0; // Not enough data to fill the image
    }

    // Call the function-under-test
    size_t bufferSize = tj3JPEGBufSize(width, height, jpegSubsamp);

    // Allocate a buffer of the calculated size
    unsigned char *jpegBuf = (unsigned char *)malloc(bufferSize);
    if (jpegBuf == NULL) {
        return 0; // Memory allocation failed
    }

    // Initialize the JPEG compression object
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        free(jpegBuf);
        return 0; // Initialization failed
    }

    // Compress the image using the fuzz input data
    int result = tjCompress2(handle, data + 3, width, 0, height, pixelFormat, &jpegBuf, &bufferSize, jpegSubsamp, 100, TJFLAG_NOREALLOC);

    // Clean up
    tjDestroy(handle);
    free(jpegBuf);

    return result == 0 ? 0 : 1; // Return 0 if successful, 1 otherwise
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
