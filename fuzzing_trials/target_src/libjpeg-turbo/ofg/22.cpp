#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize variables for tj3CompressFromYUV8
    tjhandle handle = tj3Init(TJINIT_COMPRESS); // Use TJINIT_COMPRESS instead of TJ3_COMPRESS
    if (!handle) {
        return 0; // If initialization fails, return early
    }

    // Ensure size is large enough for width, height, and subsampling
    if (size < 12) {
        tj3Destroy(handle);
        return 0;
    }

    // Extract width, height, and subsampling from the data
    int width = (int)data[0] + 1;  // Ensure width is at least 1
    int height = (int)data[1] + 1; // Ensure height is at least 1
    int subsamp = (int)data[2] % 6; // Valid subsampling values are 0-5

    // Ensure the buffer is large enough for the YUV image
    size_t yuvSize = tj3YUVBufSize(width, 4, height, subsamp); // Corrected function call to use tj3YUVBufSize
    if (size < 3 + yuvSize) {
        tj3Destroy(handle);
        return 0;
    }

    // Set YUV buffer to point to the appropriate location in data
    const unsigned char *yuvBuffer = data + 3;

    // Allocate memory for the compressed image
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Call the function under test
    int result = tj3CompressFromYUV8(handle, yuvBuffer, width, 4, height, &jpegBuf, &jpegSize);

    // Check if the compression was successful
    if (result == 0 && jpegBuf != nullptr && jpegSize > 0) {
        // Perform additional operations to ensure the compressed data is valid
        unsigned char *decompressedBuf = (unsigned char *)malloc(width * height * 3); // Assuming RGB output
        if (decompressedBuf) {
            // Corrected function call to use tj3Decompress8 with the correct number of arguments
            int decompressResult = tj3Decompress8(handle, jpegBuf, jpegSize, decompressedBuf, width * 3, TJPF_RGB);
            if (decompressResult == 0) {
                // Successfully decompressed, indicating valid coverage
                // Further processing can be added here if needed
            }
            free(decompressedBuf);
        }
    }

    // Free the compressed image buffer if it was allocated
    if (jpegBuf) {
        tj3Free(jpegBuf);
    }

    // Clean up the TurboJPEG handle
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
