#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Set up image width, height, and pixel format
    int width = 128; // Example width
    int height = 128; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format

    // Ensure the input data is large enough for the image
    if (size < static_cast<size_t>(width * height * tjPixelSize[pixelFormat])) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the compressed image
    unsigned char *compressedImage = nullptr;
    unsigned long compressedSize = 0;

    // Set up other parameters
    int jpegSubsamp = TJSAMP_444; // Example subsampling
    int jpegQual = 75; // Example quality
    int flags = 0; // Example flags

    // Allocate a buffer for the compressed image
    compressedImage = static_cast<unsigned char *>(malloc(TJBUFSIZE(width, height)));
    if (compressedImage == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjCompress(handle, const_cast<unsigned char *>(data), width, 0, height, pixelFormat,
                            compressedImage, &compressedSize, jpegSubsamp, jpegQual, flags);

    // Clean up
    if (compressedImage != nullptr) {
        tjFree(compressedImage);
    }
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
