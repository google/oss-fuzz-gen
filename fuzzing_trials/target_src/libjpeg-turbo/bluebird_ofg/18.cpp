#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for mkstemp and close
#include <stdint.h>  // Include for uint8_t
#include <sys/types.h>  // Include for size_t

extern "C" {
    #include "../src/turbojpeg.h"
    int tjSaveImage(const char *, unsigned char *, int, int, int, int, int);
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Check if the size is large enough for the image dimensions
    int width = 100;  // Arbitrary non-zero width
    int height = 100; // Arbitrary non-zero height
    int pitch = width * 3; // Assuming 3 bytes per pixel for RGB
    if (size < pitch * height) {
        return 0; // Not enough data to fill the image buffer
    }

    // Create a temporary file to store image data
    char tmpl[] = "/tmp/fuzzimageXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Initialize parameters for tjSaveImage
    const char *filename = tmpl;
    unsigned char *imageBuffer = (unsigned char *)malloc(pitch * height);
    if (imageBuffer == NULL) {
        return 0;
    }
    memcpy(imageBuffer, data, pitch * height);

    // Set arbitrary values for pixelFormat and flags
    int pixelFormat = TJPF_RGB; // Arbitrary pixel format
    int flags = 0; // No specific flags

    // Call the function-under-test
    tjSaveImage(filename, imageBuffer, width, pitch, height, pixelFormat, flags);

    // Clean up
    free(imageBuffer);
    remove(filename);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
