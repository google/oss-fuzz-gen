#include <stddef.h>
#include <stdint.h>
#include <stdio.h> // Include standard library for FILE type

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.main/src/jpeglib.h" // Include the header where J16SAMPLE is defined
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for decompression
    if (size < 10) return 0;

    // Initialize TurboJPEG decompressor
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) return 0;

    // Variables to store image properties
    int width, height, jpegSubsamp, jpegColorspace;
    
    // Get the JPEG header to understand the image dimensions and subsampling
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) != 0) {
        tjDestroy(handle);
        return 0;
    }

    // Prepare output buffer for decompressed image
    int pixelFormat = TJPF_RGB; // Example pixel format
    int pitch = width * tjPixelSize[pixelFormat];
    J16SAMPLE *buffer = new J16SAMPLE[width * height * tjPixelSize[pixelFormat]];

    // Call the function-under-test
    int result = tj3Decompress16(handle, data, size, buffer, width, pitch);

    // Clean up
    delete[] buffer;
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
