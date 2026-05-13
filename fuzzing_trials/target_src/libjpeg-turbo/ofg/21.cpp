#include <stdint.h>
#include <stdlib.h>
#include <stdio.h> // Include the standard library for FILE

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.main/src/jpeglib.h" // Include the header where J16SAMPLE is defined
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Initialize variables for tj3Compress16
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data size is large enough to simulate an image
    if (size < sizeof(J16SAMPLE) * 3) {
        tj3Destroy(handle);
        return 0;
    }

    // Create a sample image buffer
    const J16SAMPLE *imageBuffer = reinterpret_cast<const J16SAMPLE *>(data);

    // Assume a small image size for fuzzing purposes
    int width = 2;
    int height = 2;
    int pitch = width * sizeof(J16SAMPLE);
    int pixelFormat = TJPF_RGB; // RGB format for example

    // Output buffer and size
    unsigned char *compressedImage = NULL;
    size_t compressedSize = 0;

    // Call the function-under-test
    int result = tj3Compress16(handle, imageBuffer, width, pitch, height, pixelFormat, &compressedImage, &compressedSize);

    // Free the compressed image buffer if it was allocated
    if (compressedImage != NULL) {
        tj3Free(compressedImage);
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
