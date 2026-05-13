#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    // Include necessary headers and define types
    typedef void* tjhandle;
    typedef uint16_t J16SAMPLE;
}

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0;
    }

    // Ensure the input size is sufficient for the function call
    if (size < sizeof(J16SAMPLE) * 3) {
        tj3Destroy(handle);
        return 0;
    }

    // Define and initialize parameters for tj3Compress16
    const J16SAMPLE *srcBuf = reinterpret_cast<const J16SAMPLE *>(data);
    int width = 1;  // Minimal width
    int pitch = sizeof(J16SAMPLE) * width;  // Correct pitch calculation
    int height = size / pitch; // Calculate height based on available data
    int jpegSubsamp = TJSAMP_444; // Use a valid subsampling option
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Ensure height is at least 1 to perform compression
    if (height < 1) {
        height = 1;
    }

    // Call the function-under-test
    int result = tj3Compress16(handle, srcBuf, width, pitch, height, jpegSubsamp, &jpegBuf, &jpegSize);

    // Check the result to ensure the function was invoked correctly
    if (result != 0) {
        // Handle the error case if needed
    } else {
        // Simulate usage of the output to ensure code coverage
        if (jpegBuf != nullptr && jpegSize > 0) {
            // Use the jpegBuf to simulate further processing
            unsigned char *tempBuf = (unsigned char *)malloc(jpegSize);
            if (tempBuf != nullptr) {
                memcpy(tempBuf, jpegBuf, jpegSize);
                free(tempBuf);
            }
        }
    }

    // Clean up
    if (jpegBuf != nullptr) {
        tj3Free(jpegBuf);
    }
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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
