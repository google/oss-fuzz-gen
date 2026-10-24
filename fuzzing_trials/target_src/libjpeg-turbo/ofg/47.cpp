#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Call the function-under-test
    tjhandle handle = tjInitCompress();

    // Check if handle is successfully created
    if (handle == nullptr) {
        return 0;
    }

    // We should provide a minimal valid input to tjCompress2 to exercise the function
    if (size >= 12) { // Ensure there is enough data for at least a 2x2 RGB image
        int width = 2; // minimal width
        int height = 2; // minimal height
        int pitch = width * 3; // row width in bytes for RGB
        int jpegSubsamp = TJSAMP_444; // Subsampling option
        int jpegQual = 75; // Quality of compression

        unsigned char *jpegBuf = nullptr; // Buffer for the compressed JPEG image
        unsigned long jpegSize = 0; // Size of the JPEG image

        // Create a minimal RGB pixel data for a 2x2 image
        uint8_t rgbData[12];
        std::memcpy(rgbData, data, 12);

        // Compress the image
        if (tjCompress2(handle, rgbData, width, pitch, height, TJPF_RGB,
                        &jpegBuf, &jpegSize, jpegSubsamp, jpegQual, TJFLAG_NOREALLOC) == 0) {
            // Use the compressed JPEG data in some way to ensure it is processed
            // For example, decompress it back to RGB to ensure the full cycle is covered
            unsigned char *decompressedBuf = (unsigned char *)malloc(pitch * height);
            if (decompressedBuf != nullptr) {
                if (tjDecompress2(handle, jpegBuf, jpegSize, decompressedBuf, width, pitch, height, TJPF_RGB, TJFLAG_FASTDCT) == 0) {
                    // Successfully decompressed, do something with decompressedBuf if needed
                }
                free(decompressedBuf);
            }
            // Free the JPEG buffer only if compression was successful
            tjFree(jpegBuf);
        }
    }

    // Clean up by destroying the handle
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
