#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <algorithm> // For std::min

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there is enough data for width and height

    // Initialize variables
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) return 0;

    // Create a temporary file to save the image
    char tmpl[] = "/tmp/fuzzimageXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        tj3Destroy(handle);
        return 0;
    }
    close(fd);

    // Prepare image parameters
    int width = data[0] + 1; // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int pitch = width * sizeof(uint16_t); // Use uint16_t instead of J16SAMPLE
    int flags = 0;

    // Allocate memory for image buffer
    uint16_t *imageBuffer = (uint16_t *)malloc(width * height * sizeof(uint16_t)); // Use uint16_t instead of J16SAMPLE
    if (!imageBuffer) {
        tj3Destroy(handle);
        unlink(tmpl);
        return 0;
    }

    // Fill the image buffer with data
    memcpy(imageBuffer, data + 2, std::min(size - 2, width * height * sizeof(uint16_t))); // Use uint16_t instead of J16SAMPLE

    // Call the function-under-test
    int result = tj3SaveImage16(handle, tmpl, imageBuffer, width, pitch, height, flags);

    // Clean up
    free(imageBuffer);
    tj3Destroy(handle);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
