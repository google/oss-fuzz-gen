#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include for memset

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

// Since tj3CalcCompressBufSize is not declared, we need to use an alternative function
// or a calculation method that is valid for the library version in use.
// Assuming tjBufSize is a valid alternative function for buffer size calculation.

extern "C" int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Initialize variables for tj3Compress16 function
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) {
        return 0;
    }

    // Define a minimum size to ensure we have enough data for width, height, and pixel format
    if (size < sizeof(uint16_t) * 3) {
        tj3Destroy(handle);
        return 0;
    }

    // Extract width, height, and pixel format from the input data
    uint16_t width = (data[0] | (data[1] << 8)) % 256 + 1;  // Ensure non-zero width
    uint16_t height = (data[2] | (data[3] << 8)) % 256 + 1; // Ensure non-zero height
    int pixelFormat = data[4] % TJ_NUMPF; // Use modulo to ensure a valid pixel format

    // Ensure the remaining data is sufficient for the image buffer
    size_t requiredSize = sizeof(uint16_t) * width * height + 5;
    if (size < requiredSize) {
        tj3Destroy(handle);
        return 0;
    }

    // Initialize the image buffer with the input data
    const uint16_t *imageBuffer = reinterpret_cast<const uint16_t *>(data + 5);

    // Calculate pitch based on width and pixel format
    int pitch = width * tjPixelSize[pixelFormat];

    // Output buffer and size
    unsigned char *compressedBuffer = nullptr;
    size_t compressedSize = 0;

    // Prepare the destination buffer using tjBufSize
    int jpegSubsamp = TJSAMP_444; // Assuming a default subsampling
    compressedSize = tjBufSize(width, height, jpegSubsamp);
    compressedBuffer = (unsigned char *)malloc(compressedSize);
    if (!compressedBuffer) {
        tj3Destroy(handle);
        return 0;
    }
    memset(compressedBuffer, 0, compressedSize);

    // Call the function-under-test
    int result = tj3Compress16(handle, imageBuffer, width, pitch, height, pixelFormat, &compressedBuffer, &compressedSize);

    // Free the compressed buffer if it was allocated
    if (compressedBuffer) {
        tj3Free(compressedBuffer);
    }

    // Destroy the TurboJPEG handle
    tj3Destroy(handle);

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

    LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
