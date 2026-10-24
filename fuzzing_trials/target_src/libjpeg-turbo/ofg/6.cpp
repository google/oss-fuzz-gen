#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // For close()

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the necessary parameters
    if (size < sizeof(uint16_t) * 3) {
        return 0;
    }

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Create a temporary file for the image output
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        tjDestroy(handle);
        return 0;
    }
    close(fd);

    // Initialize uint16_t array
    uint16_t *samples = (uint16_t *)malloc(sizeof(uint16_t) * 3);
    if (!samples) {
        tjDestroy(handle);
        return 0;
    }
    memcpy(samples, data, sizeof(uint16_t) * 3);

    // Set image parameters
    int width = 1;  // Minimum width
    int height = 1; // Minimum height
    int pitch = width * sizeof(uint16_t);
    int flags = 0;  // No flags

    // Modify the function call to ensure it processes valid data
    // Set a valid subsampling and color space
    int subsamp = TJSAMP_444; // Use a valid subsampling option
    int colorspace = TJCS_RGB; // Use a valid color space

    // Call the function-under-test with valid parameters
    int pixelFormat = TJPF_RGB; // Use a valid pixel format
    int result = tj3SaveImage16(handle, tmpl, samples, width, pitch, height, pixelFormat);

    // Check the result of the function call
    if (result != 0) {
        // Handle the error
        tjDestroy(handle);
        free(samples);
        remove(tmpl);
        return 0;
    }

    // Cleanup
    free(samples);
    tjDestroy(handle);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
