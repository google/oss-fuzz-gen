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

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize variables for tj3Decompress16 function call
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, return early
    }

    // Assuming a reasonable maximum width and height for the decompression
    int width = 256;
    int height = 256;
    int pixelFormat = TJPF_RGB; // Use a common pixel format

    // Allocate memory for the decompressed image buffer
    uint16_t *destBuffer = (uint16_t *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (destBuffer == nullptr) {
        tjDestroy(handle);
        return 0; // If memory allocation fails, return early
    }

    // Ensure the input data is not empty and has a minimal size to be processed
    if (size > 0) {
        // Call the function-under-test
        int pitch = width * tjPixelSize[pixelFormat];
        int result = tj3Decompress16(handle, data, size, destBuffer, pitch, pixelFormat);
        if (result != 0) {
            // Handle decompression error
            tjDestroy(handle);
            free(destBuffer);
            return 0;
        }
    }

    // Clean up resources
    free(destBuffer);
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
