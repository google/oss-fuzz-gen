#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    // Define J16SAMPLE as uint16_t if not defined in the included headers
    typedef uint16_t J16SAMPLE;

    int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
        // Initialize variables
        tjhandle handle = tj3Init(TJINIT_COMPRESS);
        if (!handle) {
            return 0;
        }

        // Check if the input size is sufficient for at least one pixel
        if (size < sizeof(J16SAMPLE)) {
            tj3Destroy(handle);
            return 0;
        }

        // Use the input data as the image buffer
        const J16SAMPLE *imageBuffer = reinterpret_cast<const J16SAMPLE *>(data);

        // Define image dimensions and pixel format
        int width = 1;  // Minimum width
        int height = size / (width * sizeof(J16SAMPLE));  // Calculate height based on input size
        int pitch = width * sizeof(J16SAMPLE);
        int pixelFormat = TJPF_RGBX;  // Example pixel format

        // Allocate memory for the compressed image
        unsigned char *jpegBuf = nullptr;
        size_t jpegSize = 0;

        // Call the function-under-test
        tj3Compress16(handle, imageBuffer, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

        // Free the compressed image buffer
        tj3Free(jpegBuf);

        // Clean up
        tj3Destroy(handle);

        return 0;
    }
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
