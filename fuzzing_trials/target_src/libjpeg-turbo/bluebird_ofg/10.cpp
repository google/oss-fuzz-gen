#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0; // Ensure there's enough data for width, height, subsampling, and at least some image data
    }

    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0; // Return if initialization fails
    }

    // Extract parameters from the input data
    int width = data[0] + 1;  // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int subsampling = data[2] % 3; // Choose a valid subsampling value (0, 1, or 2)
    int padding = 4; // Typical padding for YUV planes

    // Calculate the minimum size needed for the image data
    int minImageSize = width * height * 3; // Assuming 3 bytes per pixel for RGB
    if (size < minImageSize + 3) {
        tjDestroy(handle);
        return 0; // Not enough data for the image
    }

    // Allocate memory for YUV buffer
    unsigned char *yuvBuffer = (unsigned char *)malloc(tjBufSizeYUV2(width, padding, height, subsampling));
    if (!yuvBuffer) {
        tjDestroy(handle);
        return 0; // Memory allocation failed
    }

    // Fill the source buffer with data to ensure the function is tested with meaningful input
    unsigned char *srcBuf = (unsigned char *)malloc(width * height * 3);
    if (!srcBuf) {
        free(yuvBuffer);
        tjDestroy(handle);
        return 0; // Memory allocation failed
    }
    memcpy(srcBuf, data + 3, width * height * 3);

    // Call the function-under-test with valid parameters
    int result = tjEncodeYUV3(handle, srcBuf, width, 0, height, TJPF_RGB, yuvBuffer, padding, subsampling, TJFLAG_ACCURATEDCT);

    // Check for errors
    if (result != 0) {
        // Handle error (optional logging or debugging)
    }

    // Clean up
    free(yuvBuffer);
    free(srcBuf);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
